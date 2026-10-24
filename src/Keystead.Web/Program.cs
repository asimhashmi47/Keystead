using System;
using System.Linq;
using System.Threading.RateLimiting;
using System.Threading.Tasks;
using Keystead.Infrastructure;
using Keystead.Infrastructure.Cryptography;
using Keystead.Infrastructure.Persistence;
using Keystead.Web.Api;
using Keystead.Web.Security;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

namespace Keystead.Web;

/// <summary>
/// The application entry point and composition root.
/// </summary>
/// <remarks>
/// A sealed class with a private constructor rather than a static one, because
/// <c>WebApplicationFactory&lt;T&gt;</c> cannot take a static type as its argument and the
/// integration and security suites host this exact pipeline. A marker type would work too and
/// would be one more thing to explain.
/// </remarks>
public sealed class Program
{
    private Program()
    {
    }

    /// <summary>Builds and runs the web application.</summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>A process exit code.</returns>
    public static int Main(string[] args)
    {
        // A bootstrap logger, so a failure during startup is still reported somewhere rather
        // than vanishing before the configured sink exists.
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console()
            .CreateBootstrapLogger();

        try
        {
            // A chiselled container image has no shell and no curl, so the health probe has
            // to be the application itself. Handled before the host is built: it must not
            // need a master key, a database, or anything else that could make a healthy
            // process look unhealthy.
            if (args.Contains("--healthcheck", StringComparer.Ordinal))
            {
                return RunHealthCheck();
            }

            var app = Build(args);
            app.Run();
            return 0;
        }
        catch (MasterKeyUnavailableException ex)
        {
            // Reported on its own, without a stack trace: an operator who has not supplied a
            // key needs the instruction, not a trace through the host builder.
            Log.Fatal("Keystead cannot start: {Reason}", ex.Message);
            return 78;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Keystead terminated unexpectedly during startup.");
            return 70;
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }

    /// <summary>
    /// Probes the liveness endpoint from inside the container.
    /// </summary>
    /// <remarks>
    /// Talks to loopback over plain HTTP on the port Kestrel listens on, which is why the
    /// liveness endpoint is reachable without TLS and says nothing but that the process is up.
    /// </remarks>
    /// <returns>0 when healthy, 1 otherwise.</returns>
    private static int RunHealthCheck()
    {
        var port = Environment.GetEnvironmentVariable("ASPNETCORE_HTTP_PORTS") ?? "8080";

        try
        {
            using var client = new System.Net.Http.HttpClient
            {
                Timeout = TimeSpan.FromSeconds(3),
            };

            using var response = client
                .GetAsync(new Uri($"http://127.0.0.1:{port}/healthz"))
                .GetAwaiter()
                .GetResult();

            return response.IsSuccessStatusCode ? 0 : 1;
        }
        catch (Exception ex) when (ex is System.Net.Http.HttpRequestException
            or TaskCanceledException
            or UriFormatException)
        {
            return 1;
        }
    }

    /// <summary>
    /// Builds the configured application. Separated from <see cref="Main"/> so the integration
    /// and security test suites can host the real pipeline rather than an approximation of it.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>The configured application.</returns>
    public static WebApplication Build(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        ConfigureLogging(builder);
        ConfigureKestrel(builder);
        BootstrapDevelopmentMasterKey(builder);
        ConfigureServices(builder);

        var app = builder.Build();

        ConfigurePipeline(app);
        ApplyMigrations(app);

        return app;
    }

    /// <summary>
    /// In Development only, generates a master key file if one is missing, so that
    /// <c>dotnet run</c> works on a fresh clone without manual setup.
    /// </summary>
    /// <remarks>
    /// Guarded on the environment deliberately. A server that invents its own master key on
    /// first boot would mint a fresh one after any deployment that lost the file, and every
    /// stored secret would silently become undecryptable. In Production the key must be
    /// supplied by an operator, and the application refuses to start without it.
    /// </remarks>
    private static void BootstrapDevelopmentMasterKey(WebApplicationBuilder builder)
    {
        if (!builder.Environment.IsDevelopment())
        {
            return;
        }

        var options = new MasterKeyOptions();
        builder.Configuration.GetSection(MasterKeyOptions.SectionName).Bind(options);

        if (options.Source is MasterKeySource.Environment
            || string.IsNullOrWhiteSpace(options.FilePath))
        {
            return;
        }

        if (MasterKeyBootstrapper.EnsureKeyFile(options.FilePath))
        {
            Log.Warning(
                "Generated a development master key at {Path}. This is for local development only; supply the key explicitly in Production.",
                options.FilePath);
        }
    }

    /// <summary>
    /// Applies pending migrations in Development, so a fresh clone has a usable schema.
    /// </summary>
    /// <remarks>
    /// Not done in Production. Migrating automatically on startup means several instances
    /// racing to alter the same schema during a rolling deploy, and it takes the decision to
    /// change a database that holds irreplaceable key material out of an operator's hands.
    /// DEPLOYMENT.md covers running migrations as a deliberate step.
    /// </remarks>
    private static void ApplyMigrations(WebApplication app)
    {
        if (!app.Environment.IsDevelopment())
        {
            return;
        }

        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KeysteadDbContext>();
        db.Database.Migrate();
    }

    private static void ConfigureLogging(WebApplicationBuilder builder)
    {
        builder.Host.UseSerilog((context, services, configuration) => configuration
            .ReadFrom.Configuration(context.Configuration)
            .ReadFrom.Services(services)
            .Enrich.FromLogContext()
            .Enrich.With<SecretRedactionEnricher>()
            .WriteTo.Console(
                outputTemplate:
                "[{Timestamp:HH:mm:ss} {Level:u3}] {CorrelationId} {Message:lj}{NewLine}{Exception}"));
    }

    private static void ConfigureKestrel(WebApplicationBuilder builder)
    {
        builder.WebHost.ConfigureKestrel(options =>
        {
            // A secret value can legitimately be a certificate, so the body limit is not tiny,
            // but it is bounded: an unbounded limit is a memory-exhaustion lever.
            options.Limits.MaxRequestBodySize = 1 * 1024 * 1024;
            options.Limits.MaxRequestHeadersTotalSize = 32 * 1024;
            options.Limits.MaxRequestLineSize = 8 * 1024;
            options.Limits.MaxConcurrentConnections = 1000;
            options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
            options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);

            // Do not advertise the server product and version.
            options.AddServerHeader = false;
        });
    }

    private static void ConfigureServices(WebApplicationBuilder builder)
    {
        var services = builder.Services;

        services.AddKeysteadInfrastructure(builder.Configuration);

        services.AddScoped<CspNonce>();

        // Behind a reverse proxy the real client address arrives in a header. Trusting it
        // blindly would let any client spoof its own address and defeat the IP allowlist and
        // the per-address rate limits, so the proxy list is configured explicitly and the
        // defaults (which trust only loopback) are kept until an operator widens them.
        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            options.ForwardLimit = 1;
            builder.Configuration.GetSection("Keystead:ReverseProxy").Bind(options);
        });

        services.AddDataProtection()
            .SetApplicationName("Keystead");

        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(KeysteadSchemes.MfaPending, options =>
            {
                // A separate, short-lived scheme that carries nothing but the user id between
                // the password step and the code step. Putting that id in a form field would
                // let the client change whose account it is finishing sign-in for; a
                // data-protected cookie cannot be edited.
                options.Cookie.Name = "__Host-keystead-mfa";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.Cookie.Path = "/";
                options.Cookie.IsEssential = true;

                // Long enough to read a code off a phone, short enough that an abandoned
                // half-finished sign-in does not sit around.
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                options.SlidingExpiration = false;
                options.LoginPath = "/sign-in";
            })
            .AddCookie(options =>
            {
                // The __Host- prefix is the strongest cookie binding a browser offers: it
                // requires Secure, requires Path=/, and forbids a Domain attribute, which
                // means a sibling subdomain cannot set or overwrite this cookie.
                options.Cookie.Name = "__Host-keystead-auth";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.Cookie.Path = "/";
                options.Cookie.IsEssential = true;

                options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                options.SlidingExpiration = true;

                options.LoginPath = "/sign-in";
                options.LogoutPath = "/sign-out";
                options.AccessDeniedPath = "/forbidden";
                options.ReturnUrlParameter = "next";

                // Re-checks the server-side session on every request, so revoking a session
                // takes effect immediately rather than when the cookie happens to expire.
                options.Events.OnValidatePrincipal = SessionCookieValidator.ValidateAsync;
            });

        services.AddAuthorizationBuilder()

            // Deny by default. An endpoint that forgets to state a policy gets this one, so
            // the failure mode of forgetfulness is "locked" rather than "open".
            .SetFallbackPolicy(new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build());

        services.AddAntiforgery(options =>
        {
            options.Cookie.Name = "__Host-keystead-csrf";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.Path = "/";
            options.FormFieldName = "__keystead-csrf";
            options.HeaderName = "X-Keystead-CSRF";
        });

        services.AddRazorPages(options =>
        {
            // Every state-changing handler is validated, with no per-page opt-in to forget.
            options.Conventions.ConfigureFilter(new AutoValidateAntiforgeryTokenAttribute());
        });

        services.AddRouting(options => options.LowercaseUrls = true);

        ConfigureRateLimiting(services);

        services.AddHealthChecks();

        // The OpenAPI document describes /api/v1 for SDK and client generators. Whether it is
        // exposed is decided in the pipeline: see MapOpenApiDocument.
        services.AddOpenApi("v1", options =>
        {
            options.AddDocumentTransformer((document, _, _) =>
            {
                document.Info = new Microsoft.OpenApi.OpenApiInfo
                {
                    Title = "Keystead machine API",
                    Version = "v1",
                    Description =
                        "Short-lived token authentication for applications reading secrets at "
                        + "runtime. Obtain a token from /api/v1/token with client credentials, "
                        + "then send it as a bearer token. Every response is no-store.",
                };

                document.Components ??= new Microsoft.OpenApi.OpenApiComponents();
                document.Components.SecuritySchemes ??=
                    new System.Collections.Generic.Dictionary<string, Microsoft.OpenApi.IOpenApiSecurityScheme>(System.StringComparer.Ordinal);

                document.Components.SecuritySchemes["bearer"] =
                    new Microsoft.OpenApi.OpenApiSecurityScheme
                    {
                        Type = Microsoft.OpenApi.SecuritySchemeType.Http,
                        Scheme = "bearer",
                        BearerFormat = "JWT",
                        Description =
                            "An ES256 token from /api/v1/token. Valid for minutes, not hours.",
                    };

                return System.Threading.Tasks.Task.CompletedTask;
            });
        });

        // CORS is denied unless an operator names an origin. The machine API is called by
        // servers, which do not need CORS at all; a wildcard here would only help a browser
        // page on someone else's origin use a victim's credentials.
        services.AddCors(options => options.AddDefaultPolicy(policy => policy.DisallowCredentials()));
    }

    private static void ConfigureRateLimiting(IServiceCollection services)
    {
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            // Sign-in: tight, per client address. Combined with the per-account progressive
            // lockout this bounds both "many guesses at one account" and "one guess at many
            // accounts", which a per-account limit alone would miss.
            options.AddPolicy("sign-in", context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    ClientKey(context),
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 10,
                        Window = TimeSpan.FromMinutes(5),
                        QueueLimit = 0,
                    }));

            options.AddPolicy("mfa", context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    ClientKey(context),
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 10,
                        Window = TimeSpan.FromMinutes(5),
                        QueueLimit = 0,
                    }));

            // Token issuance is a deliberate cost (it hashes a client secret), so it is capped
            // well below what a healthy deployment needs.
            options.AddPolicy("token", context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    ClientKey(context),
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 30,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                    }));

            // Secret reads are the normal workload for a running application, so this is a
            // generous ceiling whose job is to make a mass-exfiltration burst visible and slow.
            options.AddPolicy("secret-read", context =>
                RateLimitPartition.GetTokenBucketLimiter(
                    ClientKey(context),
                    _ => new TokenBucketRateLimiterOptions
                    {
                        TokenLimit = 120,
                        TokensPerPeriod = 60,
                        ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        AutoReplenishment = true,
                    }));

            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    ClientKey(context),
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 600,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                    }));
        });
    }

    /// <summary>
    /// The rate-limit partition key: the authenticated principal when there is one, otherwise
    /// the remote address.
    /// </summary>
    /// <remarks>
    /// Partitioning an authenticated request by principal rather than address matters behind
    /// NAT, where a whole office shares one address and a single busy deployment would
    /// otherwise throttle everyone beside it.
    /// </remarks>
    private static string ClientKey(HttpContext context) =>
        context.User.Identity?.IsAuthenticated == true
            ? $"user:{context.User.Identity.Name}"
            : $"ip:{context.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";

    private static void ConfigurePipeline(WebApplication app)
    {
        app.UseForwardedHeaders();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/error");

            // 6 months, subdomains included, preload-ready. Shorter is the usual advice while
            // rolling out, but this product should never be reachable over plain HTTP.
            app.UseHsts();
        }

        app.UseHttpsRedirection();

        // Headers go on before anything can start writing a body.
        app.UseMiddleware<SecurityHeadersMiddleware>();

        app.UseStaticFiles();
        app.UseRouting();
        app.UseCors();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapRazorPages();

        // Liveness: is the process up. Deliberately says nothing else, because an unauthenticated
        // endpoint that reports component status is a free reconnaissance tool.
        app.MapGet("/healthz", () => Results.Ok("ok")).AllowAnonymous();

        // Readiness: can the process serve traffic. Also intentionally terse.
        app.MapHealthChecks("/readyz").AllowAnonymous();

        app.MapMachineApi();
        MapOpenApiDocument(app);

        MapCspReportEndpoint(app);
    }

    /// <summary>
    /// Exposes the OpenAPI document.
    /// </summary>
    /// <remarks>
    /// Anonymous outside Production, and authenticated inside it. The document is a complete
    /// map of the API surface; that is exactly what a client generator wants and exactly what
    /// someone probing the installation wants, so in Production it is behind the same
    /// authorization as everything else rather than simply switched off. An operator who
    /// genuinely wants it gone can remove this call.
    /// </remarks>
    private static void MapOpenApiDocument(WebApplication app)
    {
        var endpoint = app.MapOpenApi("/openapi/v1.json");

        if (app.Environment.IsProduction())
        {
            endpoint.RequireAuthorization();
        }
        else
        {
            endpoint.AllowAnonymous();
        }
    }

    private static void MapCspReportEndpoint(WebApplication app)
    {
        app.MapPost("/csp-report", async (HttpContext context, ILogger<SecurityHeadersMiddleware> logger) =>
        {
            // A violation report is attacker-influenced input arriving unauthenticated, so it
            // is read with a hard cap and logged as data, never parsed into anything that acts.
            context.Request.EnableBuffering();
            using var reader = new System.IO.StreamReader(context.Request.Body);
            var buffer = new char[4096];
            var read = await reader.ReadAsync(buffer, context.RequestAborted).ConfigureAwait(false);

            logger.LogWarning(
                "CSP violation reported: {Report}",
                new string(buffer, 0, read));

            return Results.NoContent();
        })
        .AllowAnonymous()
        .DisableAntiforgery();
    }
}

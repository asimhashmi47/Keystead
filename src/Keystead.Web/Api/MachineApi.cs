using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Keystead.Application.Secrets;
using Keystead.Application.Tokens;
using Keystead.Domain.Common;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Keystead.Web.Api;

/// <summary>
/// The machine API under <c>/api/v1</c>.
/// </summary>
/// <remarks>
/// <para>
/// Every endpoint resolves the bearer token, then authorizes through the same
/// <c>IAccessPolicy</c> the web UI uses. The token's scopes are not the decision: they record
/// what was granted when it was minted, and the grant is re-read on each call so revoking a
/// vault assignment takes effect immediately rather than when the token expires.
/// </para>
/// <para>
/// Failures are RFC 7807 problem documents, and they are deliberately uninformative. A secret
/// in another workspace, one the identity has no grant on, and one that does not exist all
/// return the same 404, because distinguishing them would let a caller map what it cannot
/// reach.
/// </para>
/// </remarks>
public static class MachineApi
{
    private const string ProblemContentType = "application/problem+json";

    /// <summary>Maps the machine API endpoints.</summary>
    /// <param name="app">The application.</param>
    /// <returns>The same application, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="app"/> is null.</exception>
    public static WebApplication MapMachineApi(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var api = app.MapGroup("/api/v1")
            .AllowAnonymous()

            // Antiforgery does not apply: these are not browser form posts, they carry a
            // bearer token no browser will attach, and CORS is denied by default.
            .DisableAntiforgery();

        MapToken(api);
        MapSecrets(api);

        return app;
    }

    private static void MapToken(IEndpointRouteBuilder api)
    {
        api.MapPost("/token", async (
            HttpContext context,
            [FromForm] string? client_id,
            [FromForm] string? client_secret,
            [FromForm] string? grant_type,
            ITokenIssuer tokens,
            CancellationToken cancellationToken) =>
        {
            // OAuth2 client-credentials shape, so existing clients and the SDK need no
            // special casing. Only the one grant type is accepted.
            if (!string.Equals(grant_type, "client_credentials", StringComparison.Ordinal))
            {
                return Problem(
                    context,
                    StatusCodes.Status400BadRequest,
                    "unsupported_grant_type",
                    "Only the client_credentials grant is supported.");
            }

            if (string.IsNullOrEmpty(client_id) || string.IsNullOrEmpty(client_secret))
            {
                return Problem(
                    context,
                    StatusCodes.Status400BadRequest,
                    "invalid_request",
                    "Both client_id and client_secret are required.");
            }

            var issued = await tokens
                .IssueAsync(client_id, client_secret, context.ToRequestContext(), cancellationToken)
                .ConfigureAwait(false);

            if (issued.Error is { } error)
            {
                // One answer for every failure: unknown client, wrong secret, expired identity,
                // blocked address. Telling them apart would make this an enumeration oracle.
                return Problem(
                    context,
                    StatusCodes.Status401Unauthorized,
                    "invalid_client",
                    error.Message);
            }

            NoStore(context);

            return Results.Ok(new
            {
                access_token = issued.Value.AccessToken,
                token_type = "Bearer",
                expires_in = issued.Value.ExpiresInSeconds,
                scope = string.Join(' ', issued.Value.Scopes),
            });
        })
        .WithName("IssueToken")
        .RequireRateLimiting("token");
    }

    private static void MapSecrets(IEndpointRouteBuilder api)
    {
        // Metadata only. There is no value on SecretSummary, so this cannot leak one.
        api.MapGet("/vaults/{vaultId:guid}/secrets", async (
            HttpContext context,
            Guid vaultId,
            string? environment,
            ITokenIssuer tokens,
            ISecretService secrets,
            CancellationToken cancellationToken) =>
        {
            var machine = await MachineAuth.ResolveAsync(context, tokens, cancellationToken)
                .ConfigureAwait(false);

            if (machine is null)
            {
                return Unauthenticated(context);
            }

            var listed = await secrets.ListAsync(
                machine.ToPrincipal(),
                machine.WorkspaceId,
                vaultId,
                new SecretFilter(Environment: environment, IncludeDisabled: false),
                cancellationToken).ConfigureAwait(false);

            if (listed.Error is { } error)
            {
                return FromDomainError(context, error);
            }

            NoStore(context);

            return Results.Ok(listed.Value.Select(s => new
            {
                id = s.Id,
                name = s.Name,
                environment = s.Environment,
                contentType = s.ContentType,
                enabled = s.Enabled,
                expiresUtc = s.ExpiresUtc,
                latestVersion = s.LatestVersion,
                updatedUtc = s.UpdatedUtc,
                tags = s.Tags,
            }));
        })
        .WithName("ListSecrets")
        .RequireRateLimiting("secret-read");

        // Returns the value. See CLAUDE.md rule 5: permitted here because it requires a bearer
        // token no browser attaches, sends no-store, and keeps the value in the body.
        api.MapGet("/vaults/{vaultId:guid}/secrets/{name}", async (
            HttpContext context,
            Guid vaultId,
            string name,
            string? environment,
            int? version,
            ITokenIssuer tokens,
            ISecretService secrets,
            CancellationToken cancellationToken) =>
        {
            var machine = await MachineAuth.ResolveAsync(context, tokens, cancellationToken)
                .ConfigureAwait(false);

            if (machine is null)
            {
                return Unauthenticated(context);
            }

            var principal = machine.ToPrincipal();
            var env = string.IsNullOrWhiteSpace(environment) ? "prod" : environment;

            var found = await secrets.GetAsync(
                principal, machine.WorkspaceId, vaultId, name, env, cancellationToken)
                .ConfigureAwait(false);

            if (found.Error is { } lookupError)
            {
                return FromDomainError(context, lookupError);
            }

            var revealed = await secrets.RevealAsync(
                principal,
                machine.WorkspaceId,
                vaultId,
                found.Value.Id,
                version,
                context.ToRequestContext(),
                cancellationToken).ConfigureAwait(false);

            if (revealed.Error is { } revealError)
            {
                return FromDomainError(context, revealError);
            }

            using var value = revealed.Value;

            // The version identifies the content exactly, so a client can revalidate cheaply
            // without the value ever being stored by an intermediary.
            var etag = $"\"{found.Value.Id:N}-{value.Version}\"";

            if (string.Equals(
                context.Request.Headers.IfNoneMatch.ToString(),
                etag,
                StringComparison.Ordinal))
            {
                NoStore(context);
                context.Response.Headers.ETag = etag;

                return Results.StatusCode(StatusCodes.Status304NotModified);
            }

            NoStore(context);
            context.Response.Headers.ETag = etag;

            return Results.Ok(new
            {
                name = found.Value.Name,
                environment = found.Value.Environment,
                version = value.Version,
                contentType = value.ContentType,
                value = Encoding.UTF8.GetString(value.Value),
            });
        })
        .WithName("GetSecret")
        .RequireRateLimiting("secret-read");

        api.MapPut("/vaults/{vaultId:guid}/secrets/{name}", async (
            HttpContext context,
            Guid vaultId,
            string name,
            string? environment,
            SetSecretRequest body,
            ITokenIssuer tokens,
            ISecretService secrets,
            CancellationToken cancellationToken) =>
        {
            var machine = await MachineAuth.ResolveAsync(context, tokens, cancellationToken)
                .ConfigureAwait(false);

            if (machine is null)
            {
                return Unauthenticated(context);
            }

            if (body is null || string.IsNullOrEmpty(body.Value))
            {
                return Problem(
                    context,
                    StatusCodes.Status400BadRequest,
                    "invalid_request",
                    "A value is required.");
            }

            var principal = machine.ToPrincipal();
            var env = string.IsNullOrWhiteSpace(environment) ? "prod" : environment;
            var requestContext = context.ToRequestContext();
            var plaintext = Encoding.UTF8.GetBytes(body.Value);

            try
            {
                var existing = await secrets.GetAsync(
                    principal, machine.WorkspaceId, vaultId, name, env, cancellationToken)
                    .ConfigureAwait(false);

                if (existing.IsSuccess)
                {
                    var written = await secrets.SetValueAsync(
                        principal, machine.WorkspaceId, vaultId, existing.Value.Id,
                        plaintext, requestContext, cancellationToken).ConfigureAwait(false);

                    if (written.Error is { } writeError)
                    {
                        return FromDomainError(context, writeError);
                    }

                    NoStore(context);
                    return Results.Ok(new { name, environment = env, version = written.Value });
                }

                // Not found could mean "does not exist" or "not yours". Attempting the create
                // resolves it: an unauthorized caller is refused by the same policy.
                var created = await secrets.CreateAsync(
                    principal,
                    machine.WorkspaceId,
                    vaultId,
                    new CreateSecretRequest(
                        name,
                        env,
                        plaintext,
                        body.ContentType,
                        body.ExpiresUtc,
                        null,
                        new Dictionary<string, string>(StringComparer.Ordinal)),
                    requestContext,
                    cancellationToken).ConfigureAwait(false);

                if (created.Error is { } createError)
                {
                    return FromDomainError(context, createError);
                }

                NoStore(context);

                return Results.Created(
                    $"/api/v1/vaults/{vaultId:D}/secrets/{Uri.EscapeDataString(name)}?environment={Uri.EscapeDataString(env)}",
                    new { name, environment = env, version = 1 });
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        })
        .WithName("SetSecret")
        .RequireRateLimiting("secret-read");

        api.MapGet("/vaults/{vaultId:guid}/secrets/{name}/versions", async (
            HttpContext context,
            Guid vaultId,
            string name,
            string? environment,
            ITokenIssuer tokens,
            ISecretService secrets,
            CancellationToken cancellationToken) =>
        {
            var machine = await MachineAuth.ResolveAsync(context, tokens, cancellationToken)
                .ConfigureAwait(false);

            if (machine is null)
            {
                return Unauthenticated(context);
            }

            var principal = machine.ToPrincipal();
            var env = string.IsNullOrWhiteSpace(environment) ? "prod" : environment;

            var found = await secrets.GetAsync(
                principal, machine.WorkspaceId, vaultId, name, env, cancellationToken)
                .ConfigureAwait(false);

            if (found.Error is { } lookupError)
            {
                return FromDomainError(context, lookupError);
            }

            var versions = await secrets.ListVersionsAsync(
                principal, machine.WorkspaceId, vaultId, found.Value.Id, cancellationToken)
                .ConfigureAwait(false);

            if (versions.Error is { } versionsError)
            {
                return FromDomainError(context, versionsError);
            }

            NoStore(context);

            return Results.Ok(versions.Value.Select(v => new
            {
                version = v.Version,
                enabled = v.Enabled,
                createdUtc = v.CreatedUtc,
                createdBy = v.CreatedByLabel,
                sizeBytes = v.SizeBytes,
            }));
        })
        .WithName("ListSecretVersions")
        .RequireRateLimiting("secret-read");
    }

    /// <summary>The body of a set-secret request.</summary>
    /// <param name="Value">The new secret value.</param>
    /// <param name="ContentType">Optional content type hint.</param>
    /// <param name="ExpiresUtc">Optional expiry.</param>
    public sealed record SetSecretRequest(
        string Value,
        string? ContentType,
        DateTimeOffset? ExpiresUtc);

    private static void NoStore(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate, max-age=0";
        context.Response.Headers.Pragma = "no-cache";
    }

    private static IResult Unauthenticated(HttpContext context)
    {
        // Names the scheme, so a client knows what to send. Says nothing about why the token
        // was rejected, because that is the caller's problem to fix, not ours to narrate.
        context.Response.Headers.WWWAuthenticate = "Bearer";

        return Problem(
            context,
            StatusCodes.Status401Unauthorized,
            "unauthenticated",
            "A valid bearer token is required.");
    }

    private static IResult FromDomainError(HttpContext context, DomainError error) =>
        error.Kind switch
        {
            DomainErrorKind.NotFound => Problem(
                context, StatusCodes.Status404NotFound, error.Code, error.Message),

            DomainErrorKind.Conflict => Problem(
                context, StatusCodes.Status409Conflict, error.Code, error.Message),

            DomainErrorKind.Invalid => Problem(
                context, StatusCodes.Status400BadRequest, error.Code, error.Message),

            // A machine cannot step up, so a step-up requirement is a flat refusal here rather
            // than a challenge. Reported as 403 with the real reason, because this one is
            // actionable: the operator needs to grant the identity the vault.
            _ => Problem(
                context, StatusCodes.Status403Forbidden, error.Code, error.Message),
        };

    private static IResult Problem(
        HttpContext context,
        int status,
        string code,
        string detail)
    {
        NoStore(context);

        return Results.Json(
            new
            {
                type = $"https://keystead.dev/problems/{code}",
                title = ReasonFor(status),
                status,
                detail,

                // The correlation id, so an operator can find the matching audit entry and log
                // lines without the response having to explain itself.
                instance = System.Diagnostics.Activity.Current?.Id ?? context.TraceIdentifier,
            },
            statusCode: status,
            contentType: ProblemContentType);
    }

    private static string ReasonFor(int status) =>
        status switch
        {
            StatusCodes.Status400BadRequest => "Bad Request",
            StatusCodes.Status401Unauthorized => "Unauthorized",
            StatusCodes.Status403Forbidden => "Forbidden",
            StatusCodes.Status404NotFound => "Not Found",
            StatusCodes.Status409Conflict => "Conflict",
            StatusCodes.Status429TooManyRequests => "Too Many Requests",
            _ => status.ToString(CultureInfo.InvariantCulture),
        };
}

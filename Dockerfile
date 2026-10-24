# syntax=docker/dockerfile:1
#
# Keystead container image.
#
# Multi-stage, chiselled runtime, non-root, read-only root filesystem. The point of each of
# those is in the comments below rather than left as received wisdom.

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Project files first, so a change to source code does not invalidate the restore layer.
COPY Directory.Build.props Directory.Packages.props ./
COPY src/Keystead.Domain/*.csproj          src/Keystead.Domain/
COPY src/Keystead.Application/*.csproj     src/Keystead.Application/
COPY src/Keystead.Infrastructure/*.csproj  src/Keystead.Infrastructure/
COPY src/Keystead.Web/*.csproj             src/Keystead.Web/
COPY src/Keystead.Client/*.csproj          src/Keystead.Client/

RUN dotnet restore src/Keystead.Web/Keystead.Web.csproj

COPY src/ src/
COPY .editorconfig ./

# Published Release, no app host (the chiselled image has the runtime), and
# InvariantGlobalization is already set in Directory.Build.props.
RUN dotnet publish src/Keystead.Web/Keystead.Web.csproj \
        --configuration Release \
        --no-restore \
        --output /app \
    && rm -rf /app/*.pdb

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
# Chiselled: no shell, no package manager, no busybox. There is nothing in the image for an
# attacker who achieves code execution to pivot with, and the image is a fraction of the size.
# It also means you cannot `docker exec` a shell into it to debug, which is the trade.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS runtime

# The chiselled images already run as a non-root user (uid 64198). Stated explicitly so that
# the intent survives a base image change.
USER 64198:64198

WORKDIR /app
COPY --from=build --chown=64198:64198 /app .

# Kestrel listens on 8080 rather than 80, because binding a port below 1024 needs a capability
# this container does not have and should not be given.
ENV ASPNETCORE_HTTP_PORTS=8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_gcServer=1

EXPOSE 8080

# The database lives on a mounted volume, not in the image layer. A container filesystem is
# ephemeral, and a secrets database that disappears on redeploy is an outage with no recovery.
ENV Keystead__Database__Path=/data/keystead.db

VOLUME ["/data"]

# The master key is read from a mounted file, never baked in and never an environment variable
# in the image definition. See DEPLOYMENT.md.
ENV Keystead__MasterKey__Source=File \
    Keystead__MasterKey__FilePath=/run/secrets/keystead-master-key

# Hits the liveness endpoint, which deliberately reports nothing but that the process is up.
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD ["/app/Keystead.Web", "--healthcheck"]

ENTRYPOINT ["/app/Keystead.Web"]

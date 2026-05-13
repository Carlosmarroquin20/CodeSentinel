# syntax=docker/dockerfile:1.7

# --- Build stage ------------------------------------------------------------
# The full .NET 8 SDK image has everything needed to restore, build, and publish.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

WORKDIR /src

# Copy only the files needed to restore first, so the layer cache survives
# code-only changes. Project references are explicit so transitive csproj
# files must also be present at restore time.
COPY Directory.Build.props Directory.Packages.props ./
COPY src/CodeSentinel.Core/CodeSentinel.Core.csproj                     src/CodeSentinel.Core/
COPY src/CodeSentinel.Application/CodeSentinel.Application.csproj       src/CodeSentinel.Application/
COPY src/CodeSentinel.Infrastructure/CodeSentinel.Infrastructure.csproj src/CodeSentinel.Infrastructure/
COPY src/CodeSentinel.Cli/CodeSentinel.Cli.csproj                       src/CodeSentinel.Cli/

RUN dotnet restore src/CodeSentinel.Cli/CodeSentinel.Cli.csproj \
    --runtime linux-x64

# Now copy the rest of the source and publish.
COPY src/ src/

RUN dotnet publish src/CodeSentinel.Cli/CodeSentinel.Cli.csproj \
    --configuration Release \
    --runtime linux-x64 \
    --self-contained true \
    --no-restore \
    --output /app/publish \
    -p:PublishSingleFile=true \
    -p:DebugType=None \
    -p:DebugSymbols=false

# --- Runtime stage ----------------------------------------------------------
# Chiseled runtime-deps: minimal Ubuntu with the native dependencies .NET needs,
# but no shell, no package manager, no apt — drastically smaller attack surface.
# Runs as a non-root user by default.
FROM mcr.microsoft.com/dotnet/runtime-deps:8.0-jammy-chiseled AS runtime

# Repositories will be bind-mounted here at runtime.
WORKDIR /scan

COPY --from=build /app/publish /opt/codesentinel

ENTRYPOINT ["/opt/codesentinel/codesentinel"]

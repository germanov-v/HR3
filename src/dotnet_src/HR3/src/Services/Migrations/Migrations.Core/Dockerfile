FROM mcr.microsoft.com/dotnet/runtime:9.0 AS base
USER $APP_UID
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["src/Services/Migrations/Migrations.Core/Migrations.Core.csproj", "src/Services/Migrations/Migrations.Core/"]
RUN dotnet restore "src/Services/Migrations/Migrations.Core/Migrations.Core.csproj"
COPY . .
WORKDIR "/src/src/Services/Migrations/Migrations.Core"
RUN dotnet build "./Migrations.Core.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Migrations.Core.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Migrations.Core.dll"]

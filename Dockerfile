FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy csproj and restore as distinct layers
COPY ["Personal_OneDrive_Backend.csproj", "./"]
RUN dotnet restore "Personal_OneDrive_Backend.csproj"

# Copy everything else and build
COPY . .
RUN dotnet publish "Personal_OneDrive_Backend.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Build runtime image
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

# Expose ports based on production environment variables (usually 80 or 8080)
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

ENTRYPOINT ["dotnet", "Personal_OneDrive_Backend.dll"]

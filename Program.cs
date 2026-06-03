using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Graph;
using Microsoft.Identity.Web;
using StackExchange.Redis;
using Microsoft.Kiota.Abstractions.Authentication;
using Microsoft.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

var redisConnectionString = builder.Configuration.GetConnectionString("Redis");
ConfigurationOptions? redisConfig = null;
var useRedis = false;

if (!string.IsNullOrEmpty(redisConnectionString))
{
    try
    {
        redisConfig = ConfigurationOptions.Parse(redisConnectionString);
        useRedis = true;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[CRITICAL] Redis String Parsing Failed: {ex.Message}");
        useRedis = false;
    }
}

// IDistributedCache: Redis if possible, otherwise in‑memory
if (useRedis && redisConfig != null)
{
    builder.Services.AddStackExchangeRedisCache(options =>
    {
        options.ConfigurationOptions = redisConfig;
        options.InstanceName = "TokenCache_";
    });

    try
    {
        var redis = ConnectionMultiplexer.Connect(redisConfig);
        builder.Services.AddDataProtection()
            .PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[DATA PROTECTION ERROR] Redis connection failed: {ex.Message}");
    }
}
else
{
    Console.WriteLine("[INFO] Redis not available, falling back to in‑memory cache. Tokens will be lost on restart.");
    builder.Services.AddDistributedMemoryCache();
}

builder.Services.AddOpenApi();

// Plain OIDC web-app sign-in (no MSAL downstream-API token acquisition).
// We deliberately do NOT call EnableTokenAcquisitionToCallDownstreamApi: that makes MSAL
// redeem the auth code and keep the refresh token in its own cache, where GetTokenAsync
// cannot reach it. With plain sign-in + SaveTokens + the offline_access scope, the OIDC
// handler redeems the code itself and the access AND refresh tokens land in the auth
// properties, so /login-success can capture the refresh token and persist it to Upstash.
builder.Services.AddMicrosoftIdentityWebAppAuthentication(builder.Configuration, "AzureAd");

builder.Services.Configure<Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions>(
    Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectDefaults.AuthenticationScheme,
    options =>
    {
        options.SaveTokens = true;
        options.ResponseType = "code";
        // Graph delegated scope used for OneDrive, plus offline_access to receive a refresh token.
        options.Scope.Add("Files.ReadWrite");
        options.Scope.Add("offline_access");
    });

builder.Services.Configure<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

builder.Services.AddAuthorization();

builder.Services.AddCors(options =>
{
    options.AddPolicy("StrictStaticSite", policy =>
    {
        var allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();

        if (builder.Environment.IsDevelopment())
        {
            policy.SetIsOriginAllowed(_ => true)
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        }
        else
        {
            var origins = allowedOrigins.ToList();
            origins.Add("https://tagea2026.onrender.com");
            origins.Add("https://rhp2026.onrender.com");
            origins.Add("https://wws2026.onrender.com");
            policy.WithOrigins(origins.ToArray())
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        }
    });
});

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();

app.Use((context, next) =>
{
    context.Request.Scheme = "https";
    return next();
});

app.UseForwardedHeaders();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors("StrictStaticSite");

app.UseCookiePolicy(new CookiePolicyOptions
{
    MinimumSameSitePolicy = Microsoft.AspNetCore.Http.SameSiteMode.None,
    Secure = CookieSecurePolicy.Always
});

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok("OK")).AllowAnonymous();

// The set of OneDrive folders the API is allowed to serve. Each frontend page maps to
// one of these. Add a new entry here to expose a new page's folder.
List<string> allowedFolders = new List<string> { "TaGea2026", "RHP2026", "WWS2026" };

// Default folder used when a request does not specify ?folder=, so existing pages that
// predate the multi-folder support keep working without any frontend change.
string foldername = "TaGea2026";

// Resolves the target folder from the ?folder= query string, validating it against the
// allowlist (case-insensitive). Returns the default folder when none is supplied, or null
// when an unknown folder is requested so the caller can reject it.
string? ResolveFolder(HttpRequest request)
{
    var requested = request.Query["folder"].ToString();
    if (string.IsNullOrWhiteSpace(requested))
        return foldername;

    return allowedFolders.FirstOrDefault(f => string.Equals(f, requested, StringComparison.OrdinalIgnoreCase));
}

// Scope set sent to the token endpoint on refresh. offline_access keeps the
// refresh token rotating so the 90-day sliding window is renewed on every use.
const string graphScopes = "Files.ReadWrite offline_access";

// Helper: use the stored refresh token to silently obtain a new access token.
// This is what makes the app survive cold starts: as long as Upstash still holds
// refresh_token:{accountId}, no interactive login is needed.
async Task<string?> TryRefreshTokenAsync(string accountId, IDistributedCache cache, IConfiguration config)
{
    var refreshToken = await cache.GetStringAsync($"refresh_token:{accountId}");
    if (string.IsNullOrEmpty(refreshToken))
    {
        Console.WriteLine($"[REFRESH] No refresh_token cached for {accountId}. " +
            "It was either never captured at login or the cache (Upstash) did not persist it across restart.");
        return null;
    }

    var tenantId = config["AzureAd:TenantId"];
    var clientId = config["AzureAd:ClientId"];
    var clientSecret = config["AzureAd:ClientSecret"];
    if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
    {
        Console.WriteLine($"[REFRESH] Missing AzureAd config (tenantId/clientId/clientSecret). " +
            $"tenantId set: {!string.IsNullOrEmpty(tenantId)}, clientId set: {!string.IsNullOrEmpty(clientId)}, clientSecret set: {!string.IsNullOrEmpty(clientSecret)}.");
        return null;
    }

    using var http = new HttpClient();
    var tokenResponse = await http.PostAsync(
        $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token",
        new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "refresh_token"),
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("client_secret", clientSecret),
            new KeyValuePair<string, string>("refresh_token", refreshToken),
            new KeyValuePair<string, string>("scope", graphScopes)
        }));

    if (!tokenResponse.IsSuccessStatusCode)
    {
        var errorBody = await tokenResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"[REFRESH] Microsoft rejected refresh_token grant for {accountId}. " +
            $"Status {(int)tokenResponse.StatusCode}. Body: {errorBody}");
        return null;
    }

    using var json = System.Text.Json.JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
    var root = json.RootElement;

    var newAccessToken = root.GetProperty("access_token").GetString();
    if (string.IsNullOrEmpty(newAccessToken)) return null;

    await cache.SetStringAsync($"token:{accountId}", newAccessToken, new DistributedCacheEntryOptions
    {
        AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1)
    });

    // Microsoft rotates the refresh token on each redemption. Persist the new one so the
    // 90-day sliding window restarts; failing to do so would silently expire the session.
    if (root.TryGetProperty("refresh_token", out var newRt) && !string.IsNullOrEmpty(newRt.GetString()))
    {
        await cache.SetStringAsync($"refresh_token:{accountId}", newRt.GetString()!, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(90)
        });
    }

    Console.WriteLine($"[REFRESH] Obtained a new access token for {accountId} via refresh token.");
    return newAccessToken;
}

// Helper: build a Graph client from the cached access token keyed by X-Microsoft-Account-Id,
// silently refreshing via the stored refresh token when the access token is missing/expired.
async Task<GraphServiceClient?> GetAuthenticatedGraphClientAsync(HttpRequest request, IConfiguration config, IDistributedCache cache)
{
    if (!request.Headers.TryGetValue("X-Microsoft-Account-Id", out var accountId) || string.IsNullOrEmpty(accountId))
    {
        Console.WriteLine("[AUTH ERROR] Missing X-Microsoft-Account-Id header.");
        return null;
    }

    var accessToken = await cache.GetStringAsync($"token:{accountId}") ?? string.Empty;

    if (string.IsNullOrEmpty(accessToken))
    {
        Console.WriteLine($"[AUTH] No access token for {accountId}, attempting silent refresh...");
        accessToken = await TryRefreshTokenAsync(accountId!, cache, config) ?? string.Empty;
        if (string.IsNullOrEmpty(accessToken))
        {
            Console.WriteLine($"[AUTH ERROR] Token refresh failed for {accountId}. Re-login required.");
            return null;
        }
    }

    var authProvider = new BaseBearerTokenAuthenticationProvider(new InMemoryTokenProvider(accessToken));
    return new GraphServiceClient(authProvider);
}

// OIDC login
app.MapGet("/login", async (HttpContext context) =>
{
    await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
    {
        RedirectUri = "/login-success"
    });
});

// Capture the access + refresh tokens saved on the auth cookie (SaveTokens=true) during
// interactive login and persist them to Upstash so background, cookie-less calls work.
app.MapGet("/login-success", async (HttpContext context, IDistributedCache cache) =>
{
    var userId = context.User.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;

    if (!string.IsNullOrEmpty(userId))
    {
        try
        {
            var accessToken = await context.GetTokenAsync("access_token");
            if (!string.IsNullOrEmpty(accessToken))
            {
                await cache.SetStringAsync($"token:{userId}", accessToken, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1)
                });
                Console.WriteLine($"[SUCCESS] Cached access token for {userId}.");
            }
            else
            {
                Console.WriteLine($"[WARN] No access_token on the auth cookie for {userId}. " +
                    "Check that the OIDC handler has SaveTokens=true and the Files.ReadWrite scope.");
            }

            var refreshToken = await context.GetTokenAsync("refresh_token");
            if (!string.IsNullOrEmpty(refreshToken))
            {
                await cache.SetStringAsync($"refresh_token:{userId}", refreshToken, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(90)
                });
                Console.WriteLine($"[SUCCESS] Cached refresh token for {userId}. Cold-start silent refresh is now enabled.");
            }
            else
            {
                Console.WriteLine($"[WARN] No refresh_token on the auth cookie for {userId}. " +
                    "The offline_access scope must be requested and EnableTokenAcquisitionToCallDownstreamApi must NOT be in use, " +
                    "otherwise the refresh token never reaches the cookie and 90-day silent refresh cannot work.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARN] Could not capture tokens during login: {ex.GetType().Name}: {ex.Message}");
        }
    }

    return Results.Json(new
    {
        userId,
        message = "Authentication successful. Use this userId as X-Microsoft-Account-Id in your frontend."
    });
});

// Optional helper for debugging from frontend
app.MapGet("/whoami", (HttpContext context) =>
{
    var userId = context.User.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;
    return Results.Json(new { userId });
});

// Diagnostic: reports whether tokens for an account survive in the cache (Upstash).
// Does NOT return token values. Protected by the custom API key outside Development.
app.MapGet("/debug/token-state", async (HttpRequest request, IConfiguration config, IDistributedCache cache, IWebHostEnvironment env) =>
{
    if (!env.IsDevelopment())
    {
        if (!request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || extractedKey != config["CustomApiKey"])
            return Results.Unauthorized();
    }

    if (!request.Headers.TryGetValue("X-Microsoft-Account-Id", out var accountId) || string.IsNullOrEmpty(accountId))
        return Results.BadRequest("Missing X-Microsoft-Account-Id header.");

    var accessToken = await cache.GetStringAsync($"token:{accountId}");
    var refreshToken = await cache.GetStringAsync($"refresh_token:{accountId}");

    return Results.Json(new
    {
        accountId = accountId.ToString(),
        accessTokenCached = !string.IsNullOrEmpty(accessToken),
        // The one that matters for cold starts. If this is false right after login, capture failed.
        // If it is true after login but false after a cold start, Upstash is not persisting.
        refreshTokenCached = !string.IsNullOrEmpty(refreshToken)
    });
});

app.MapGet("/get-image-list", async (HttpRequest request, IConfiguration config, IDistributedCache cache, IWebHostEnvironment env) =>
{
    if (!env.IsDevelopment())
    {
        if (!request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || extractedKey != config["CustomApiKey"])
            return Results.Unauthorized();
    }

    try
    {
        var graphClient = await GetAuthenticatedGraphClientAsync(request, config, cache);
        if (graphClient == null) return Results.BadRequest("Missing or invalid background authentication data.");

        var folderName = ResolveFolder(request);
        if (folderName == null) return Results.BadRequest("Unknown folder.");

        // Use Me.Drive (personal OneDrive-safe)
        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;

        // Resolve folder safely
        var folder = await graphClient.Drives[userDriveId]
            .Root
            .ItemWithPath(folderName)
            .GetAsync();

        if (folder == null || folder.Id == null)
            return Results.Problem("Folder not found in OneDrive.");

        var childrenResponse = await graphClient.Drives[userDriveId]
            .Items[folder.Id]
            .Children
            .GetAsync();

        var items = childrenResponse?.Value ?? new List<Microsoft.Graph.Models.DriveItem>();
        var fileNames = items.Select(item => item.Name).ToList();

        return Results.Ok(fileNames);
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed: {ex.Message}");
    }
});

app.MapGet("/download-all-images", async (HttpContext context, IConfiguration config, IDistributedCache cache, IWebHostEnvironment env) =>
{
    if (!env.IsDevelopment())
    {
        if (!context.Request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || extractedKey != config["CustomApiKey"])
        {
            context.Response.StatusCode = 401;
            return;
        }
    }

    try
    {
        var graphClient = await GetAuthenticatedGraphClientAsync(context.Request, config, cache);
        if (graphClient == null)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Missing or invalid authentication data.");
            return;
        }

        var folderName = ResolveFolder(context.Request);
        if (folderName == null)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Unknown folder.");
            return;
        }

        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;
        if (string.IsNullOrWhiteSpace(userDriveId))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Unable to resolve the current user's drive.");
            return;
        }

        var folder = await graphClient.Drives[userDriveId]
            .Root
            .ItemWithPath(folderName)
            .GetAsync();

        if (folder == null || folder.Id == null)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("Folder not found.");
            return;
        }

        var childrenResponse = await graphClient.Drives[userDriveId]
            .Items[folder.Id]
            .Children
            .GetAsync();

        var files = (childrenResponse?.Value ?? new List<Microsoft.Graph.Models.DriveItem>())
            .Where(i => i.Folder == null)
            .ToList();

        if (files.Count == 0)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("No files found.");
            return;
        }

        const int maxFilesPerZip = 100;
        const long maxTotalZipBytes = 250L * 1024 * 1024;

        var limitedFiles = new List<Microsoft.Graph.Models.DriveItem>();
        var estimatedTotalBytes = 0L;

        foreach (var file in files)
        {
            if (limitedFiles.Count >= maxFilesPerZip)
                break;

            var fileSize = file.Size ?? 0;
            if (estimatedTotalBytes + fileSize > maxTotalZipBytes)
                break;

            limitedFiles.Add(file);
            estimatedTotalBytes += fileSize;
        }

        if (limitedFiles.Count == 0)
        {
            context.Response.StatusCode = 413;
            await context.Response.WriteAsync("Requested file set exceeds the per-request safety limit.");
            return;
        }

        context.Response.ContentType = "application/zip";
        context.Response.Headers.Append("Content-Disposition", "attachment; filename=\"images.zip\"");

        using var archive = new System.IO.Compression.ZipArchive(context.Response.Body, System.IO.Compression.ZipArchiveMode.Create);
        foreach (var file in limitedFiles)
        {
            if (file.Id == null || file.Name == null) continue;

            var contentStream = await graphClient.Drives[userDriveId].Items[file.Id].Content.GetAsync();
            if (contentStream != null)
            {
                var zipEntry = archive.CreateEntry(file.Name);
                using var entryStream = zipEntry.Open();
                await contentStream.CopyToAsync(entryStream);
            }
        }
    }
    catch (Exception ex)
    {
        if (!context.Response.HasStarted)
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync($"Failed: {ex.Message}");
        }
    }
});

app.MapPost("/upload-images", async (HttpRequest request, IConfiguration config, IDistributedCache cache, IWebHostEnvironment env) =>
{
    if (!env.IsDevelopment())
    {
        if (!request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || extractedKey != config["CustomApiKey"])
            return Results.Unauthorized();
    }

    try
    {
        var graphClient = await GetAuthenticatedGraphClientAsync(request, config, cache);
        if (graphClient == null)
            return Results.BadRequest("Invalid authentication initialization data.");

        var folderName = ResolveFolder(request);
        if (folderName == null) return Results.BadRequest("Unknown folder.");

        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;
        if (string.IsNullOrWhiteSpace(userDriveId))
            return Results.BadRequest("Unable to resolve the current user's drive.");

        if (!request.HasFormContentType)
            return Results.BadRequest("Invalid multipart upload request.");

        if (!Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType) || string.IsNullOrWhiteSpace(contentType.Boundary.Value))
            return Results.BadRequest("Missing multipart boundary.");

        var boundary = Microsoft.Net.Http.Headers.HeaderUtilities.RemoveQuotes(contentType.Boundary).Value;
        if (string.IsNullOrWhiteSpace(boundary))
            return Results.BadRequest("Missing multipart boundary.");

        var reader = new MultipartReader(boundary, request.Body)
        {
            HeadersCountLimit = 32,
            BodyLengthLimit = long.MaxValue
        };

        var uploadedFiles = new List<string>();
        MultipartSection? section;

        while ((section = await reader.ReadNextSectionAsync()) != null)
        {
            if (!Microsoft.Net.Http.Headers.ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var disposition))
                continue;

            var hasFileName = !string.IsNullOrEmpty(disposition.FileName.Value) || !string.IsNullOrEmpty(disposition.FileNameStar.Value);
            if (!disposition.DispositionType.Equals("form-data", StringComparison.OrdinalIgnoreCase) || !hasFileName)
                continue;

            var fileName = Path.GetFileName(disposition.FileNameStar.Value ?? disposition.FileName.Value);
            if (string.IsNullOrWhiteSpace(fileName))
                continue;

            var uploadSessionRequestBody = new Microsoft.Graph.Drives.Item.Items.Item.CreateUploadSession.CreateUploadSessionPostRequestBody
            {
                Item = new Microsoft.Graph.Models.DriveItemUploadableProperties
                {
                    Name = fileName,
                    AdditionalData = new Dictionary<string, object>
                    {
                        ["@microsoft.graph.conflictBehavior"] = "rename"
                    }
                }
            };

            var uploadSession = await graphClient.Drives[userDriveId]
                .Root
                .ItemWithPath($"{folderName}/{fileName}")
                .CreateUploadSession
                .PostAsync(uploadSessionRequestBody);

            if (uploadSession?.UploadUrl == null)
                return Results.Problem($"Failed to create upload session for {fileName}.");

            var uploadTask = new LargeFileUploadTask<Microsoft.Graph.Models.DriveItem>(
                uploadSession,
                section.Body,
                320 * 1024,
                graphClient.RequestAdapter);

            var uploadResult = await uploadTask.UploadAsync();
            if (!uploadResult.UploadSucceeded)
                return Results.Problem($"Upload did not complete for {fileName}.");

            uploadedFiles.Add(fileName);
        }

        if (uploadedFiles.Count == 0)
            return Results.BadRequest("No files uploaded.");

        return Results.Ok(new { Message = "Files uploaded successfully", Files = uploadedFiles });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[UPLOAD ERROR] {ex}");
        return Results.Problem($"Upload failed: {ex.Message}");
    }
}).WithName("UploadImages");


app.MapGet("/get-homepage-images/{count}", async (int count, HttpRequest request, IConfiguration config, IDistributedCache cache, IWebHostEnvironment env) =>
{
    if (!env.IsDevelopment())
    {
        if (!request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || extractedKey != config["CustomApiKey"])
            return Results.Unauthorized();
    }

    try
    {
        var graphClient = await GetAuthenticatedGraphClientAsync(request, config, cache);
        if (graphClient == null) return Results.BadRequest("Invalid initialization metadata.");

        var folderName = ResolveFolder(request);
        if (folderName == null) return Results.BadRequest("Unknown folder.");

        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;
        if (string.IsNullOrWhiteSpace(userDriveId)) return Results.BadRequest("Unable to resolve the current user's drive.");

        var folder = await graphClient.Drives[userDriveId]
            .Root
            .ItemWithPath(folderName)
            .GetAsync();

        if (folder == null || folder.Id == null)
            return Results.Ok(new List<object>());

        var childrenResponse = await graphClient.Drives[userDriveId]
            .Items[folder.Id]
            .Children
            .GetAsync();

        var files = (childrenResponse?.Value ?? new List<Microsoft.Graph.Models.DriveItem>())
            .Where(i => i.Folder == null && i.Name != null)
            .ToList();

        if (files.Count == 0) return Results.Ok(new List<object>());

        var random = new Random();
        var randomImages = files
            .OrderBy(x => random.Next())
            .Take(count)
            .Select(i => new
            {
                Name = i.Name,
                Id = i.Id,
                DownloadUrl = i.AdditionalData != null && i.AdditionalData.ContainsKey("@microsoft.graph.downloadUrl")
                    ? i.AdditionalData["@microsoft.graph.downloadUrl"]?.ToString()
                    : i.WebUrl
            })
            .ToList();

        return Results.Ok(randomImages);
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed: {ex.Message}");
    }
});


app.MapGet("/get-all-download-urls", async (HttpRequest request, IConfiguration config, IDistributedCache cache, IWebHostEnvironment env) =>
{
    if (!env.IsDevelopment())
    {
        if (!request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || extractedKey != config["CustomApiKey"])
            return Results.Unauthorized();
    }

    try
    {
        var graphClient = await GetAuthenticatedGraphClientAsync(request, config, cache);
        if (graphClient == null) return Results.BadRequest("Invalid initialization metadata.");

        var folderName = ResolveFolder(request);
        if (folderName == null) return Results.BadRequest("Unknown folder.");

        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;
        if (string.IsNullOrWhiteSpace(userDriveId)) return Results.BadRequest("Unable to resolve the current user's drive.");

        var folder = await graphClient.Drives[userDriveId]
            .Root
            .ItemWithPath(folderName)
            .GetAsync();

        if (folder == null || folder.Id == null)
            return Results.Ok(new List<object>());

        var childrenResponse = await graphClient.Drives[userDriveId]
            .Items[folder.Id]
            .Children
            .GetAsync();

        var files = (childrenResponse?.Value ?? new List<Microsoft.Graph.Models.DriveItem>())
            .Where(i => i.Folder == null && i.Name != null)
            .ToList();

        if (files.Count == 0) return Results.Ok(new List<object>());

        var allImages = files
            .Select(i => new
            {
                Name = i.Name,
                Id = i.Id,
                DownloadUrl = i.AdditionalData != null && i.AdditionalData.ContainsKey("@microsoft.graph.downloadUrl")
                    ? i.AdditionalData["@microsoft.graph.downloadUrl"]?.ToString()
                    : i.WebUrl
            })
            .ToList();

        return Results.Ok(allImages);
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed: {ex.Message}");
    }
});

app.Run();

public class InMemoryTokenProvider : IAccessTokenProvider
{
    private readonly string _token;
    public InMemoryTokenProvider(string token) => _token = token;

    public Task<string> GetAuthorizationTokenAsync(
        Uri uri,
        Dictionary<string, object>? additionalContext = null,
        CancellationToken cancellationToken = default)
        => Task.FromResult(_token);

    public AllowedHostsValidator AllowedHostsValidator { get; } = new();
}

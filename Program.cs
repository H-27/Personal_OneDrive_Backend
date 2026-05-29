using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Graph;
using Microsoft.Identity.Web;
using StackExchange.Redis;
using Microsoft.Kiota.Abstractions.Authentication;

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

builder.Services.AddMicrosoftIdentityWebAppAuthentication(builder.Configuration, "AzureAd")
    .EnableTokenAcquisitionToCallDownstreamApi(new[] { "Files.ReadWrite", "offline_access" })
    .AddMicrosoftGraph(builder.Configuration.GetSection("MicrosoftGraph"))
    .AddDistributedTokenCaches();

builder.Services.Configure<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
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
            policy.WithOrigins(allowedOrigins)
                  .AllowAnyMethod()
                  .WithHeaders("X-Custom-Auth-Key", "X-Microsoft-Account-Id", "Content-Type", "Accept", "Authorization");
        }
    });
});

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
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
    MinimumSameSitePolicy = SameSiteMode.None,
    Secure = CookieSecurePolicy.Always
});

app.UseAuthentication();
app.UseAuthorization();

string foldername = "TaGea2026";

// Helper: build Graph client from cached token keyed by X-Microsoft-Account-Id
async Task<GraphServiceClient?> GetAuthenticatedGraphClientAsync(HttpRequest request, IConfiguration config, IDistributedCache cache)
{
    if (!request.Headers.TryGetValue("X-Microsoft-Account-Id", out var accountId) || string.IsNullOrEmpty(accountId))
    {
        Console.WriteLine("[AUTH ERROR] Missing X-Microsoft-Account-Id header.");
        return null;
    }

    var customRedisKey = $"token:{accountId}";
    var accessToken = await cache.GetStringAsync(customRedisKey) ?? string.Empty;

    if (string.IsNullOrEmpty(accessToken))
    {
        Console.WriteLine($"[AUTH ERROR] No token found in custom key {customRedisKey}. Re-login required.");
        return null;
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

// Capture token during interactive login and cache it under token:{userId}
app.MapGet("/login-success", async (HttpContext context, ITokenAcquisition tokenAcquisition, IDistributedCache cache) =>
{
    var userId = context.User.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;

    if (!string.IsNullOrEmpty(userId))
    {
        try
        {
            var accessToken = await tokenAcquisition.GetAccessTokenForUserAsync(
                new[] { "Files.ReadWrite" },
                user: context.User);

            if (!string.IsNullOrEmpty(accessToken))
            {
                var customRedisKey = $"token:{userId}";
                var cacheOptions = new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1)
                };

                await cache.SetStringAsync(customRedisKey, accessToken, cacheOptions);
                Console.WriteLine($"[SUCCESS] Manually cached token under custom key: {customRedisKey}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WARN] Could not capture raw token during login: {ex.Message}");
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

        // Use Me.Drive (personal OneDrive-safe)
        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;

        // Resolve folder safely
        var folder = await graphClient.Drives[userDriveId]
            .Root
            .ItemWithPath(foldername)
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

        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;

        // Resolve folder safely
        var folder = await graphClient.Drives[userDriveId]
            .Root
            .ItemWithPath(foldername)
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

        if (files == null || files.Count == 0)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("No files found.");
            return;
        }

        context.Response.ContentType = "application/zip";
        context.Response.Headers.Append("Content-Disposition", "attachment; filename=\"images.zip\"");

        using var archive = new System.IO.Compression.ZipArchive(context.Response.Body, System.IO.Compression.ZipArchiveMode.Create);
        foreach (var file in files)
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
        if (!request.HasFormContentType) return Results.BadRequest("Invalid form content.");

        var form = await request.ReadFormAsync();
        var files = form.Files;
        if (files.Count == 0) return Results.BadRequest("No files uploaded.");

        var graphClient = await GetAuthenticatedGraphClientAsync(request, config, cache);
        if (graphClient == null) return Results.BadRequest("Invalid authentication initialization data.");

        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;
        var uploadedFiles = new List<string>();

        foreach (var file in files)
        {
            if (string.IsNullOrEmpty(file.FileName)) continue;

            using var stream = file.OpenReadStream();

            var uploadSessionRequestBody = new Microsoft.Graph.Drives.Item.Items.Item.CreateUploadSession.CreateUploadSessionPostRequestBody
            {
                Item = new Microsoft.Graph.Models.DriveItemUploadableProperties
                {
                    AdditionalData = new Dictionary<string, object>
                    {
                        { "@microsoft.graph.conflictBehavior", "replace" }
                    }
                }
            };

            var uploadSession = await graphClient.Drives[userDriveId]
                .Root
                .ItemWithPath($"{foldername}/{file.FileName}")
                .CreateUploadSession
                .PostAsync(uploadSessionRequestBody);

            var maxSliceSize = 4 * 320 * 1024;
            var fileUploadTask = new Microsoft.Graph.LargeFileUploadTask<Microsoft.Graph.Models.DriveItem>(
                uploadSession, stream, maxSliceSize, graphClient.RequestAdapter);

            await fileUploadTask.UploadAsync();
            uploadedFiles.Add(file.FileName);
        }

        return Results.Ok(new { Message = "Files uploaded successfully", Files = uploadedFiles });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed: {ex.Message}");
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

        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;

        // Resolve folder safely
        var folder = await graphClient.Drives[userDriveId]
            .Root
            .ItemWithPath(foldername)
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

        if (files == null || files.Count == 0) return Results.Ok(new List<object>());

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

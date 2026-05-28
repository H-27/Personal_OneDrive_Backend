using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Identity.Web;
using Microsoft.Graph;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

// 1. Setup unified, SSL-forced Redis Configuration for Upstash
var redisConnectionString = builder.Configuration.GetConnectionString("Redis");
ConfigurationOptions? redisConfig = null;

if (!string.IsNullOrEmpty(redisConnectionString))
{
    redisConfig = ConfigurationOptions.Parse(redisConnectionString);
    redisConfig.AbortOnConnectFail = false;
    redisConfig.Ssl = true; // Force SSL for Upstash!
}

// 2. Fix Distributed Cache (Token persistence) using the SSL configuration
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.ConfigurationOptions = redisConfig;
    options.InstanceName = "TokenCache_";
});

// 3. Fix Data Protection (Cookie persistence) using the same connection
if (redisConfig != null)
{
    var redis = ConnectionMultiplexer.Connect(redisConfig);
    builder.Services.AddDataProtection()
        .PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys");
}

builder.Services.AddOpenApi();

builder.Services.AddMicrosoftIdentityWebAppAuthentication(builder.Configuration, "AzureAd")
    .EnableTokenAcquisitionToCallDownstreamApi(new string[] { "Files.ReadWrite", "offline_access" })
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
    options.AddPolicy("StrictStaticSite",
        policy => {
            var allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
            if (builder.Environment.IsDevelopment())
            {
                policy.SetIsOriginAllowed(_ => true);
            }
            else
            {
                policy.WithOrigins(allowedOrigins);
            }
            policy.AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        });
});

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();

// Explicitly handle Render HTTPS routing context early
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

// Endpoints
app.MapGet("/login", async (HttpContext context) =>
{
    await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
    {
        RedirectUri = "/login-success"
    });
});

app.MapGet("/login-success", (HttpContext context) =>
{
    return Results.Ok("Authentication successful! Your backend is now linked to OneDrive.");
});

app.MapGet("/get-image-list", async (HttpRequest request, IConfiguration config, GraphServiceClient graphClient, IWebHostEnvironment env) =>
{
    if (!env.IsDevelopment())
    {
        if (!request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || extractedKey != config["CustomApiKey"])
            return Results.Unauthorized();
    }
    try
    {
        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;
        var childrenResponse = await graphClient.Drives[userDriveId].Root.ItemWithPath(foldername).Children.GetAsync();
        var fileNames = childrenResponse?.Value?.Select(item => item.Name).ToList();
        return Results.Ok(fileNames);
    }
    catch (Exception ex) { return Results.Problem($"Failed: {ex.Message}"); }
}).RequireAuthorization();

app.MapGet("/download-all-images", async (HttpContext context, IConfiguration config, GraphServiceClient graphClient, IWebHostEnvironment env) =>
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
        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;
        var childrenResponse = await graphClient.Drives[userDriveId].Root.ItemWithPath(foldername).Children.GetAsync();
        var files = childrenResponse?.Value?.Where(i => i.Folder == null).ToList();
        if (files == null || files.Count == 0)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("No files found.");
            return;
        }

        context.Response.ContentType = "application/zip";
        context.Response.Headers.Append("Content-Disposition", "attachment; filename=\"images.zip\"");

        using (var archive = new System.IO.Compression.ZipArchive(context.Response.Body, System.IO.Compression.ZipArchiveMode.Create))
        {
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
    }
    catch (Exception ex)
    {
        if (!context.Response.HasStarted)
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync($"Failed: {ex.Message}");
        }
    }
}).RequireAuthorization();

app.MapPost("/upload-images", async (HttpRequest request, IConfiguration config, GraphServiceClient graphClient, IWebHostEnvironment env) =>
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
                    AdditionalData = new Dictionary<string, object> { { "@microsoft.graph.conflictBehavior", "replace" } }
                }
            };

            var uploadSession = await graphClient.Drives[userDriveId].Root.ItemWithPath($"{foldername}/{file.FileName}").CreateUploadSession.PostAsync(uploadSessionRequestBody);
            
            // Optimization: Bump slice size to 1.25MB (Must be a multiple of 320KB) to dramatically speed up upload times
            int maxSliceSize = 4 * 320 * 1024; 
            var fileUploadTask = new Microsoft.Graph.LargeFileUploadTask<Microsoft.Graph.Models.DriveItem>(uploadSession, stream, maxSliceSize, graphClient.RequestAdapter);
            await fileUploadTask.UploadAsync();
                
            uploadedFiles.Add(file.FileName);
        }
        return Results.Ok(new { Message = "Files uploaded successfully", Files = uploadedFiles });
    }
    catch (Exception ex) { return Results.Problem($"Failed: {ex.Message}"); }
}).WithName("UploadImages").RequireAuthorization();

app.MapGet("/get-homepage-images/{count}", async (int count, HttpRequest request, IConfiguration config, GraphServiceClient graphClient, IWebHostEnvironment env) =>
{
    if (!env.IsDevelopment())
    {
        if (!request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || extractedKey != config["CustomApiKey"])
            return Results.Unauthorized();
    }
    try
    {
        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;
        var childrenResponse = await graphClient.Drives[userDriveId].Root.ItemWithPath(foldername).Children.GetAsync();
        var files = childrenResponse?.Value?.Where(i => i.Folder == null && i.Name != null).ToList();
        if (files == null || files.Count == 0) return Results.Ok(new List<object>());

        var random = new Random();
        var randomImages = files.OrderBy(x => random.Next()).Take(count).Select(i => new 
        { 
            Name = i.Name, 
            Id = i.Id,
            DownloadUrl = i.AdditionalData != null && i.AdditionalData.ContainsKey("@microsoft.graph.downloadUrl")
                ? i.AdditionalData["@microsoft.graph.downloadUrl"]?.ToString() 
                : i.WebUrl
        }).ToList();
        return Results.Ok(randomImages);
    }
    catch (Exception ex) { return Results.Problem($"Failed: {ex.Message}"); }
}).RequireAuthorization();

app.Run();
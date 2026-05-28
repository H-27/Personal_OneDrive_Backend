using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Identity.Web;
using Microsoft.Graph;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;

// Initialize the web server
var builder = WebApplication.CreateBuilder(args);

// Setup persistent Redis Cache so graph tokens survive container restarts
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
    options.InstanceName = "TokenCache_";
});

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddMicrosoftIdentityWebAppAuthentication(builder.Configuration, "AzureAd")
    .EnableTokenAcquisitionToCallDownstreamApi(new string[] { "Files.ReadWrite", "offline_access" })
    .AddMicrosoftGraph(builder.Configuration.GetSection("MicrosoftGraph"))
    .AddDistributedTokenCaches();

// Force the session cookie to allow Cross-Origin requests
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
                // Unrestricted in development for easier testing
                policy.SetIsOriginAllowed(_ => true);
            }
            else
            {
                // Strict origins in production
                policy.WithOrigins(allowedOrigins);
            }
            
            policy.AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials(); // Allows cookies/auth headers to be sent
        });
});

// Configure proxy forwarding so ASP.NET knows Caddy is providing HTTPS
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();

app.UseForwardedHeaders();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// Apply the CORS policy so your frontend can call the backend
app.UseCors("StrictStaticSite");

// Enable Cookie Policy for Cross-Origin cookies
app.UseCookiePolicy(new CookiePolicyOptions
{
    MinimumSameSitePolicy = SameSiteMode.None,
    Secure = CookieSecurePolicy.Always
});

// Enable authentication/authorization middleware
app.UseAuthentication();
app.UseAuthorization();

string foldername = "TaGea2026"; // Set the folder name

// 1. Kicks off the Microsoft Login Sequence
app.MapGet("/login", async (HttpContext context) =>
{
    // This tells .NET to challenge the user via Microsoft Identity OpenIdConnect.
    // It automatically forces a redirect to the Microsoft Accounts sign-in page.
    await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
    {
        RedirectUri = "/login-success" // Where to go AFTER a successful login
    });
});

// 2. A simple landing page showing the login worked
app.MapGet("/login-success", (HttpContext context) =>
{
    return Results.Ok("Authentication successful! Your backend is now linked to OneDrive. You can close this tab and test /get-image_list.");
});

// Get a list of images in the folder and return it as a JSON response
app.MapGet("/get-image-list", async (HttpRequest request, IConfiguration config, GraphServiceClient graphClient, IWebHostEnvironment env) =>
{
    // 1. Check if the request contains our custom secret header (Skip in Development)
    if (!env.IsDevelopment())
    {
        if (!request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || 
            extractedKey != config["CustomApiKey"])
        {
            return Results.Unauthorized(); // Block them with a 401 Unauthorized instantly
        }
    }

    try
    {
        // 1. Get your drive ID
        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;

        // 2. Target the children OF the specific folder path
        // Syntax: /drives/{drive-id}/root:/{folder-name}:/children
        var childrenResponse = await graphClient.Drives[userDriveId]
            .Root
            .ItemWithPath(foldername)
            .Children
            .GetAsync();

        // 3. Extract the file names from the Value collection
        // childrenResponse.Value contains the list of files/folders inside TaGea2026
        var fileNames = childrenResponse?.Value?
            .Select(item => item.Name)
            .ToList();

        return Results.Ok(fileNames);
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to get OneDrive files: {ex.Message}");
    }
})
.WithName("GetImageList")
.RequireAuthorization();

// Download all images in the folder as a zip file
app.MapGet("/download-all-images", async (HttpRequest request, IConfiguration config, GraphServiceClient graphClient, IWebHostEnvironment env) =>
{
    // 1. Check if the request contains our custom secret header (Skip in Development)
    if (!env.IsDevelopment())
    {
        if (!request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || 
            extractedKey != config["CustomApiKey"])
        {
            return Results.Unauthorized(); // Block them with a 401 Unauthorized instantly
        }
    }

    try
    {
        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;

        var childrenResponse = await graphClient.Drives[userDriveId]
            .Root
            .ItemWithPath(foldername)
            .Children
            .GetAsync();

        var files = childrenResponse?.Value?.Where(i => i.Folder == null).ToList();
        if (files == null || files.Count == 0)
        {
            return Results.NotFound("No files found to download.");
        }

        using var memoryStream = new MemoryStream();
        using (var archive = new System.IO.Compression.ZipArchive(memoryStream, System.IO.Compression.ZipArchiveMode.Create, true))
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
        
        memoryStream.Position = 0;
        return Results.File(memoryStream.ToArray(), "application/zip", "images.zip");
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to download images: {ex.Message}");
    }
})
.WithName("DownloadAllImages")
.RequireAuthorization();

// Upload images to the folder
app.MapPost("/upload-images", async (HttpRequest request, IConfiguration config, GraphServiceClient graphClient, IWebHostEnvironment env) =>
{
    // 1. Check if the request contains our custom secret header (Skip in Development)
    if (!env.IsDevelopment())
    {
        if (!request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || 
            extractedKey != config["CustomApiKey"])
        {
            return Results.Unauthorized(); // Block them with a 401 Unauthorized instantly
        }
    }

    try
    {
        if (!request.HasFormContentType)
        {
            return Results.BadRequest("Invalid form content type. Ensure you are sending multipart/form-data.");
        }

        var form = await request.ReadFormAsync();
        var files = form.Files;

        if (files.Count == 0)
        {
            return Results.BadRequest("No files were uploaded.");
        }

        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;

        var uploadedFiles = new List<string>();

        foreach (var file in files)
        {
            if (string.IsNullOrEmpty(file.FileName)) continue;

            using var stream = file.OpenReadStream();
            await graphClient.Drives[userDriveId]
                .Root
                .ItemWithPath($"{foldername}/{file.FileName}")
                .Content
                .PutAsync(stream);
                
            uploadedFiles.Add(file.FileName);
        }

        return Results.Ok(new { Message = "Files uploaded successfully", Files = uploadedFiles });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to upload images: {ex.Message}");
    }
}).WithName("UploadImages")
.RequireAuthorization();

// Get n random images from the folder for display on the homepage
app.MapGet("/get-homepage-images/{count}", async (int count, HttpRequest request, IConfiguration config, GraphServiceClient graphClient, IWebHostEnvironment env) =>
{
    // 1. Check if the request contains our custom secret header (Skip in Development)
    if (!env.IsDevelopment())
    {
        if (!request.Headers.TryGetValue("X-Custom-Auth-Key", out var extractedKey) || 
            extractedKey != config["CustomApiKey"])
        {
            return Results.Unauthorized(); // Block them with a 401 Unauthorized instantly
        }
    }

    try
    {
        var driveItem = await graphClient.Me.Drive.GetAsync();
        var userDriveId = driveItem?.Id;

        var childrenResponse = await graphClient.Drives[userDriveId]
            .Root
            .ItemWithPath(foldername)
            .Children
            .GetAsync();

        var files = childrenResponse?.Value?
            .Where(i => i.Folder == null && i.Name != null)
            .ToList();

        if (files == null || files.Count == 0)
        {
            return Results.Ok(new List<object>());
        }

        var random = new Random();
        var randomImages = files.OrderBy(x => random.Next()).Take(count).Select(i => new 
        { 
            Name = i.Name, 
            Id = i.Id,
            // Grab the raw file download URL instead of the OneDrive viewer wrapper page
            DownloadUrl = i.AdditionalData != null && i.AdditionalData.ContainsKey("@microsoft.graph.downloadUrl")
                ? i.AdditionalData["@microsoft.graph.downloadUrl"]?.ToString() 
                : i.WebUrl
        }).ToList();

        return Results.Ok(randomImages);
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to get homepage images: {ex.Message}");
    }
}).WithName("GetHomepageImages")
.RequireAuthorization();

app.Run();

// dotnet user-secrets set "OneDriveApiKey"
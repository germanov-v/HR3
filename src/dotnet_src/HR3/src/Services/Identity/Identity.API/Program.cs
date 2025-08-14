using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddHttpClient();

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.LoginPath = "/signin/yandex"; // можно выбрать дефолт
        options.LogoutPath = "/logout";
        options.Cookie.Name = "auth.demo";
        options.SlidingExpiration = true;
    })

    // 1) Яндекс (OAuth 2.0)
    .AddOAuth("yandex", options =>
    {
        options.ClientId = builder.Configuration["Authentication:Yandex:ClientId"]!;
        options.ClientSecret = builder.Configuration["Authentication:Yandex:ClientSecret"]!;
        options.CallbackPath = "/auth/callback-yandex";

        options.AuthorizationEndpoint = "https://oauth.yandex.ru/authorize";
        options.TokenEndpoint = "https://oauth.yandex.ru/token";
        options.UserInformationEndpoint = "https://login.yandex.ru/info";

        options.Scope.Add("login:email"); // по желанию

        options.SaveTokens = true;
        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
        options.ClaimActions.MapJsonKey(ClaimTypes.Name, "display_name");
        options.ClaimActions.MapJsonKey(ClaimTypes.Email, "default_email");

        options.Events = new OAuthEvents
        {
            OnCreatingTicket = async ctx =>
            {
                using var response = await ctx.Backchannel.GetAsync(options.UserInformationEndpoint,
                    ctx.HttpContext.RequestAborted);
                response.EnsureSuccessStatusCode();

                using var stream = await response.Content.ReadAsStreamAsync();
                using var doc = await JsonDocument.ParseAsync(stream);

                ctx.RunClaimActions(doc.RootElement);
            }
        };
    });

var app = builder.Build();


app.MapGet("/signin/{provider}", (HttpContext http, string provider) =>
{
    var supported = new[] { "yandex", "vk", "sber" };
    if (!supported.Contains(provider))
        return Results.BadRequest(new { error = "Unsupported provider" });

    var props = new AuthenticationProperties
    {
        RedirectUri = "/me" 
    };
    return Results.Challenge(props, new[] { provider });
});

app.MapGet("/me", (ClaimsPrincipal user) =>
{
    if (user?.Identity?.IsAuthenticated != true)
        return Results.Unauthorized();

    var result = new
    {
        name = user.Identity!.Name,
        claims = user.Claims.Select(c => new { c.Type, c.Value, c.Issuer })
    };
    return Results.Ok(result);
});

app.MapPost("/logout", async (HttpContext http) =>
{
    await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { ok = true });
});


app.MapGet("/", () => "Hello World!");

app.Run();
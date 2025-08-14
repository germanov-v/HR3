using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.IdentityModel.Tokens;
// ... твои using-ы из кода

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient();

// ===== JWT options =====
var jwtSection = builder.Configuration.GetSection("Jwt");
var jwtIssuer   = jwtSection["Issuer"];
var jwtAudience = jwtSection["Audience"];
var jwtKey      = jwtSection["Key"];
var signingKey  = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!));

// ===== auth как у тебя (cookie + yandex) =====
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.LoginPath = "/signin/yandex";
        options.LogoutPath = "/logout";
        options.Cookie.Name = "auth.demo";
        options.SlidingExpiration = true;
    })
    .AddOAuth("yandex", options =>
    {
        options.ClientId = builder.Configuration["Authentication:Yandex:ClientId"]!;
        options.ClientSecret = builder.Configuration["Authentication:Yandex:ClientSecret"]!;
        options.CallbackPath = "/auth/callback-yandex";

        options.AuthorizationEndpoint = "https://oauth.yandex.ru/authorize";
        options.TokenEndpoint = "https://oauth.yandex.ru/token";
        options.UserInformationEndpoint = "https://login.yandex.ru/info";

        options.Scope.Add("login:email");
        options.Scope.Add("login:info"); 
        options.Scope.Add("login:avatar");
        options.SaveTokens = true;
        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
        options.ClaimActions.MapJsonKey(ClaimTypes.Name, "display_name");
        options.ClaimActions.MapJsonKey(ClaimTypes.Email, "default_email");

        options.Events = new OAuthEvents
        {
            OnCreatingTicket = async ctx =>
            {
                // var accessToken = ctx.AccessToken!;
                // var userInfoUrl = $"{options.UserInformationEndpoint}?format=json&oauth_token={accessToken}";
                //
                // using var response = await ctx.Backchannel.GetAsync(userInfoUrl, ctx.HttpContext.RequestAborted);
                // response.EnsureSuccessStatusCode();
                //
                // using var stream = await response.Content.ReadAsStreamAsync();
                // using var doc = await JsonDocument.ParseAsync(stream);
                //
                // ctx.RunClaimActions(doc.RootElement);
                var url = $"{options.UserInformationEndpoint}?format=json&oauth_token={ctx.AccessToken}";
                using var resp = await ctx.Backchannel.GetAsync(url, ctx.HttpContext.RequestAborted);
                resp.EnsureSuccessStatusCode();

                using var stream = await resp.Content.ReadAsStreamAsync();
                using var doc = await JsonDocument.ParseAsync(stream);

                ctx.RunClaimActions(doc.RootElement);
            }
        };
    });
builder.Services.AddAuthorization();
var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();


// /oauth/yandex/start?returnUrl=...
app.MapGet("/oauth/yandex/start", (HttpContext http, string? returnUrl) =>
{
    // После успешного входа вернемся на наш post-signin с исходным returnUrl
    var props = new AuthenticationProperties
    {
        RedirectUri = $"/oauth/post-signin{(string.IsNullOrWhiteSpace(returnUrl) ? "" : $"?returnUrl={Uri.EscapeDataString(returnUrl)}")}"
    };
    return Results.Challenge(props, new[] { "yandex" });
});


// OAuth handler уже положил Identity в cookie (в рамках ЭТОГО API)
app.MapGet("/oauth/post-signin", (HttpContext http, string? returnUrl) =>
{
    if (http.User?.Identity?.IsAuthenticated != true)
        return Results.Unauthorized();

    // Сгенерим наш JWT на основе клеймов пользователя
    var token = IssueJwt(http.User, jwtIssuer!, jwtAudience!, signingKey);

    if (!string.IsNullOrWhiteSpace(returnUrl))
    {
        // Вернем пользователя в MVC-клиент с access_token в query
        var sep = returnUrl.Contains('?') ? "&" : "?";
        var redirect = $"{returnUrl}{sep}access_token={Uri.EscapeDataString(token)}";
        return Results.Redirect(redirect);
    }

    // Если returnUrl не передали — просто JSON
    return Results.Json(new { access_token = token });
});

// === Твои предыдущие ручки можно оставить для отладки ===
app.MapGet("/signin/{provider}", (HttpContext http, string provider) =>
{
    var supported = new[] { "yandex" /*, "vk","sber"*/ };
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
    return Results.Ok(new
    {
        name = user.Identity!.Name,
        claims = user.Claims.Select(c => new { c.Type, c.Value, c.Issuer })
    });
});

app.MapPost("/logout", async (HttpContext http) =>
{
    await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { ok = true });
});

app.MapGet("/", () => "Hello World!");

app.Run();

// ===== helper: выпуск JWT =====
static string IssueJwt(ClaimsPrincipal principal, string issuer, string audience, SecurityKey key)
{
    var now = DateTime.UtcNow;
    var claims = principal.Claims.ToList();

    // гарантируем наличие NameIdentifier как sub
    var sub = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value
              ?? claims.FirstOrDefault(c => c.Type == "sub")?.Value
              ?? Guid.NewGuid().ToString("N");

    var jwt = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        claims: claims.Append(new Claim("sub", sub)).DistinctBy(c => (c.Type, c.Value)),
        notBefore: now,
        expires: now.AddHours(2),
        signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
    );
    return new JwtSecurityTokenHandler().WriteToken(jwt);
}

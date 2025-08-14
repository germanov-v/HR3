using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient();

// ===== JWT options (валидация конфигурации) =====
var jwtSection   = builder.Configuration.GetSection("Jwt");
var jwtIssuer    = jwtSection["Issuer"]    ?? throw new InvalidOperationException("Missing Jwt:Issuer");
var jwtAudience  = jwtSection["Audience"]  ?? throw new InvalidOperationException("Missing Jwt:Audience");
var jwtKey       = jwtSection["Key"]       ?? throw new InvalidOperationException("Missing Jwt:Key");
var signingKey   = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

// ===== OAuth: Яндекс =====
var yandexId     = builder.Configuration["Authentication:Yandex:ClientId"]
                   ?? throw new InvalidOperationException("Missing Authentication:Yandex:ClientId");
var yandexSecret = builder.Configuration["Authentication:Yandex:ClientSecret"]
                   ?? throw new InvalidOperationException("Missing Authentication:Yandex:ClientSecret");

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
        options.ClientId = yandexId;
        options.ClientSecret = yandexSecret;

        // ВАЖНО: этот путь должен совпадать с Redirect URI в кабинете Яндекса
        options.CallbackPath = "/auth/callback-yandex";

        options.AuthorizationEndpoint   = "https://oauth.yandex.ru/authorize";
        options.TokenEndpoint           = "https://oauth.yandex.ru/token";
        options.UserInformationEndpoint = "https://login.yandex.ru/info";

        // Нужные разрешения
        options.Scope.Add("login:email");
        options.Scope.Add("login:info");
        options.Scope.Add("login:avatar");

        options.SaveTokens = true;

        // Базовые клеймы из JSON
        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
        options.ClaimActions.MapJsonKey(ClaimTypes.Email, "default_email");
        options.ClaimActions.MapJsonKey(ClaimTypes.GivenName, "first_name");
        options.ClaimActions.MapJsonKey(ClaimTypes.Surname, "last_name");
        options.ClaimActions.MapJsonKey("urn:yandex:login", "login");
        options.ClaimActions.MapJsonKey("urn:yandex:display_name", "display_name");
        options.ClaimActions.MapJsonKey("urn:yandex:avatar_id", "default_avatar_id");

        options.Events = new OAuthEvents
        {
            OnCreatingTicket = async ctx =>
            {
                // Яндекс ожидает access_token (в query или в заголовке)
                var url = $"{options.UserInformationEndpoint}?format=json&oauth_token={ctx.AccessToken}";

                using var resp = await ctx.Backchannel.GetAsync(url, ctx.HttpContext.RequestAborted);
                resp.EnsureSuccessStatusCode();

                using var stream = await resp.Content.ReadAsStreamAsync();
                using var doc = await JsonDocument.ParseAsync(stream);
                var root = doc.RootElement;

                // Применяем маппинг
                ctx.RunClaimActions(root);

                // Надежно выставим Name (фолбэки)
                string? pick(params string[] keys)
                {
                    foreach (var k in keys)
                        if (root.TryGetProperty(k, out var v) && !string.IsNullOrWhiteSpace(v.GetString()))
                            return v.GetString();
                    return null;
                }

                var name = pick("real_name", "display_name", "login", "default_email");
                if (!string.IsNullOrWhiteSpace(name))
                {
                    ((ClaimsIdentity)ctx.Principal!.Identity!).AddClaim(new Claim(ClaimTypes.Name, name!));
                }
            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseHttpsRedirection();       // для корректной работы localhost https
app.UseAuthentication();
app.UseAuthorization();

// ====== ФЛОУ ======

// 1) Старт OAuth — редирект на Яндекс. Можно передать returnUrl (куда вернем пользователя после входа)
app.MapGet("/oauth/yandex/start", (HttpContext http, string? returnUrl) =>
{
    var props = new AuthenticationProperties
    {
        RedirectUri = $"/oauth/post-signin{(string.IsNullOrWhiteSpace(returnUrl) ? "" : $"?returnUrl={Uri.EscapeDataString(returnUrl)}")}"
    };
    return Results.Challenge(props, new[] { "yandex" });
});

// 2) После успешного коллбэка (Cookie создана в этом сервисе) — выдаем наш JWT и редиректим обратно
app.MapGet("/oauth/post-signin", (HttpContext http, string? returnUrl) =>
{
    if (http.User?.Identity?.IsAuthenticated != true)
        return Results.Unauthorized();

    var token = IssueJwt(http.User, jwtIssuer, jwtAudience, signingKey);

    if (!string.IsNullOrWhiteSpace(returnUrl))
    {
        var sep = returnUrl.Contains('?') ? "&" : "?";
        return Results.Redirect($"{returnUrl}{sep}access_token={Uri.EscapeDataString(token)}");
    }

    return Results.Json(new { access_token = token });
});

// ====== Отладочные ручки ======
app.MapGet("/signin/{provider}", (HttpContext http, string provider) =>
{
    if (provider != "yandex")
        return Results.BadRequest(new { error = "Unsupported provider" });

    var props = new AuthenticationProperties { RedirectUri = "/me" };
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

app.MapGet("/", () => "Auth API is up");

app.Run();

// ===== helper: выпуск JWT =====
static string IssueJwt(ClaimsPrincipal principal, string issuer, string audience, SecurityKey key)
{
    var now = DateTime.UtcNow;
    var claims = principal.Claims.ToList();

    // sub обязателен
    var sub = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value
              ?? claims.FirstOrDefault(c => c.Type == "sub")?.Value
              ?? Guid.NewGuid().ToString("N");

    // уникализируем пары (Type, Value), чтобы не дублировать
    var unique = claims
        .Append(new Claim("sub", sub))
        .GroupBy(c => (c.Type, c.Value))
        .Select(g => g.First());

    var jwt = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        claims: unique,
        notBefore: now,
        expires: now.AddHours(2),
        signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
    );
    return new JwtSecurityTokenHandler().WriteToken(jwt);
}

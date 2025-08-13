# Требуемые сервисы авторизации

1. Яндекс авторизация
2. Вк
3. Сбер
4. Telegram


### Draft .NET Core

```csharp

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient();

// Cookie + разные схемы провайдеров
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
    })

    // 2) VK (OAuth 2.0)
    .AddOAuth("vk", options =>
    {
        options.ClientId = builder.Configuration["Authentication:VK:ClientId"]!;
        options.ClientSecret = builder.Configuration["Authentication:VK:ClientSecret"]!;
        options.CallbackPath = "/auth/callback-vk";

        options.AuthorizationEndpoint = "https://oauth.vk.com/authorize";
        options.TokenEndpoint = "https://oauth.vk.com/access_token";
        options.UserInformationEndpoint = "https://api.vk.com/method/users.get";

        options.Scope.Add("email"); // выдаёт email в токен‑ответе
        options.SaveTokens = true;

        // VK возвращает часть данных прямо в ответе токена (user_id, email)
        options.Events = new OAuthEvents
        {
            OnCreatingTicket = async ctx =>
            {
                var accessToken = ctx.AccessToken!;
                // запросим профиль
                var userInfoUrl =
                    $"{options.UserInformationEndpoint}?access_token={Uri.EscapeDataString(accessToken)}&v=5.199&fields=photo_200,screen_name";
                using var response = await ctx.Backchannel.GetAsync(userInfoUrl, ctx.HttpContext.RequestAborted);
                response.EnsureSuccessStatusCode();

                using var stream = await response.Content.ReadAsStreamAsync();
                using var doc = await JsonDocument.ParseAsync(stream);

                var user = doc.RootElement.GetProperty("response")[0];

                var vkId = user.GetProperty("id").GetInt64().ToString();
                var name = $"{user.GetProperty("first_name").GetString()} {user.GetProperty("last_name").GetString()}";
                var screenName = user.TryGetProperty("screen_name", out var sn) ? sn.GetString() : null;
                var photo = user.TryGetProperty("photo_200", out var ph) ? ph.GetString() : null;

                var identity = (ClaimsIdentity)ctx.Principal!.Identity!;
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, vkId, ClaimValueTypes.String, "vk"));
                identity.AddClaim(new Claim(ClaimTypes.Name, name));
                if (!string.IsNullOrEmpty(screenName))
                    identity.AddClaim(new Claim("urn:vk:screen_name", screenName));
                if (!string.IsNullOrEmpty(photo))
                    identity.AddClaim(new Claim("urn:vk:photo", photo));

                // email может прийти в токен‑ответе
                var email = ctx.TokenResponse.Response?.RootElement.TryGetProperty("email", out var em) == true
                    ? em.GetString()
                    : null;
                if (!string.IsNullOrEmpty(email))
                    identity.AddClaim(new Claim(ClaimTypes.Email, email!));
            }
        };
    })

    // 3) Сбер ID (OpenID Connect)
    // Важно: у Сбера разные окружения и выданный в кабинете Issuer/Authority.
    // Подставьте точный Authority из кабинета Сбер ID.
    .AddOpenIdConnect("sber", options =>
    {
        options.Authority = builder.Configuration["Authentication:Sber:Authority"]!; // например, "https://id.sber.ru" (пример; используйте значение из кабинета)
        options.ClientId = builder.Configuration["Authentication:Sber:ClientId"]!;
        options.ClientSecret = builder.Configuration["Authentication:Sber:ClientSecret"]!;
        options.CallbackPath = "/auth/callback-sber";

        options.ResponseType = "code";
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;

        // OIDC стандартные клеймы + e‑mail (если доступен)
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email"); // если разрешено в кабинете

        // Иногда требуется принудительно указать метаданные:
        // options.MetadataAddress = builder.Configuration["Authentication:Sber:MetadataAddress"];
        // options.RequireHttpsMetadata = true;
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// ====== Маршруты ======

// Точка входа на провайдера
app.MapGet("/signin/{provider}", (HttpContext http, string provider) =>
{
    var supported = new[] { "yandex", "vk", "sber" };
    if (!supported.Contains(provider))
        return Results.BadRequest(new { error = "Unsupported provider" });

    var props = new AuthenticationProperties
    {
        RedirectUri = "/me" // куда вернёмся после успешного входа
    };
    return Results.Challenge(props, new[] { provider });
});

// Telegram Login Widget — присылает query‑параметры, проверяем подпись и логиним
app.MapPost("/auth/telegram", async (HttpContext http) =>
{
    // Документация Telegram: формируем data_check_string, считаем HMAC-SHA256 по ключу SHA256(botToken)
    var form = await http.Request.ReadFormAsync();
    var data = form.ToDictionary(k => k.Key, v => v.Value.ToString());

    var botToken = app.Configuration["Authentication:Telegram:BotToken"];
    if (string.IsNullOrEmpty(botToken))
        return Results.BadRequest(new { error = "Telegram bot token not configured" });

    if (!ValidateTelegramAuth(data, botToken!))
        return Results.Unauthorized();

    var userJson = JsonDocument.Parse(data["user"]).RootElement;
    var tgId = userJson.GetProperty("id").GetInt64().ToString();
    var firstName = userJson.TryGetProperty("first_name", out var fn) ? fn.GetString() : "";
    var lastName = userJson.TryGetProperty("last_name", out var ln) ? ln.GetString() : "";
    var username = userJson.TryGetProperty("username", out var un) ? un.GetString() : null;

    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, tgId, ClaimValueTypes.String, "telegram"),
        new(ClaimTypes.Name, $"{firstName} {lastName}".Trim())
    };
    if (!string.IsNullOrEmpty(username))
        claims.Add(new Claim("urn:telegram:username", username!));

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

    return Results.Redirect("/me");
});

// Текущий пользователь
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

// Выход
app.MapPost("/logout", async (HttpContext http) =>
{
    await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok(new { ok = true });
});

app.Run();

static bool ValidateTelegramAuth(IDictionary<string, string> data, string botToken)
{
    // Telegram присылает: auth_date, hash, и др. поля; поле user — JSON
    if (!data.TryGetValue("hash", out var hash)) return false;

    var pairs = data
        .Where(kv => kv.Key != "hash")
        .OrderBy(kv => kv.Key, StringComparer.Ordinal)
        .Select(kv => $"{kv.Key}={kv.Value}");

    var dataCheckString = string.Join("\n", pairs);

    using var sha = SHA256.Create();
    var secretKey = sha.ComputeHash(Encoding.UTF8.GetBytes(botToken));

    using var hmac = new HMACSHA256(secretKey);
    var computed = hmac.ComputeHash(Encoding.UTF8.GetBytes(dataCheckString));
    var hex = BitConverter.ToString(computed).Replace("-", "").ToLowerInvariant();

    return hex == hash.ToLowerInvariant();
}


```

```json

{
  "Authentication": {
    "Yandex": {
      "ClientId": "your_yandex_client_id",
      "ClientSecret": "your_yandex_client_secret"
    },
    "VK": {
      "ClientId": "your_vk_app_id",
      "ClientSecret": "your_vk_secure_key"
    },
    "Sber": {
      "Authority": "https://<issuer-from-sber-cabinet>", 
      "ClientId": "your_sber_client_id",
      "ClientSecret": "your_sber_client_secret",
      "MetadataAddress": ""
    },
    "Telegram": {
      "BotToken": "123456789:ABCDEF..."
    }
  }
}

```
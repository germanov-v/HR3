using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Web.Controllers;

public class AuthController : Controller
{
    private readonly AuthApiOptions _authApi;
    private readonly TokenValidationParameters _validationParams;
    private readonly JwtSecurityTokenHandler _handler = new();

    public AuthController(IOptions<AuthApiOptions> authApi, TokenValidationParameters validationParams)
    {
        _authApi = authApi.Value;
        _validationParams = validationParams;
    }

    // // Кнопка "Войти" отправляет сюда
    // [HttpGet("/auth/signin")]
    // public IActionResult SignIn(string? returnUrl = null)
    // {
    //     // Куда вернётся Auth-API после Яндекса
    //     var callback = Url.ActionLink("Callback", "Auth", null, Request.Scheme)!;
    //
    //     // Редиректим пользователя в наш Auth-API для старта OAuth с Яндексом
    //     var startUrl = $"{_authApi.BaseUrl.TrimEnd('/')}/oauth/yandex/start?returnUrl={Uri.EscapeDataString(callback)}";
    //     return Redirect(startUrl);
    // }
    
    [HttpGet("/auth/signin")]
    public IActionResult SignIn([FromQuery] string provider = "yandex", string? returnUrl = null)
    {
        var callback = Url.ActionLink("Callback", "Auth", null, Request.Scheme)!;
        var startUrl = $"{_authApi.BaseUrl.TrimEnd('/')}/oauth/{provider}/start?returnUrl={Uri.EscapeDataString(callback)}";
        return Redirect(startUrl);
    }

    // Auth-API возвращает сюда: ?access_token=...&refresh_token=...(опционально)
    [HttpGet("/auth/callback")]
    public async Task<IActionResult> Callback([FromQuery] string? access_token, [FromQuery] string? refresh_token)
    {
        if (string.IsNullOrWhiteSpace(access_token))
            return BadRequest("Missing access_token");

        try
        {
            // Валидируем JWT, полученный от Auth-API
            var principal = _handler.ValidateToken(access_token, _validationParams, out var validatedToken);

            // Создаём локальную cookie-сессию только для MVC
            var authProps = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(8)
            };

            // Можно сохранить refresh_token в зашифрованный cookie/хранилище (опционально)
            if (!string.IsNullOrWhiteSpace(refresh_token))
            {
                authProps.StoreTokens(new[]
                {
                    new AuthenticationToken { Name = "refresh_token", Value = refresh_token }
                });
            }

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(new ClaimsIdentity(principal.Claims, CookieAuthenticationDefaults.AuthenticationScheme)),
                authProps
            );

            // После входа — на защищённую страницу
            return RedirectToAction("Secure", "Home");
        }
        catch (SecurityTokenException ex)
        {
            return Unauthorized($"Invalid token: {ex.Message}");
        }
    }

    [HttpPost("/auth/logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Index", "Home");
    }
}
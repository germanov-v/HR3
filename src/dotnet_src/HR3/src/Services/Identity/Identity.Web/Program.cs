using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/auth/signin";
        o.LogoutPath = "/auth/logout";
        o.Cookie.Name = "mvc.ui.auth";
        o.SlidingExpiration = true;
    });

builder.Services.AddAuthorization();

// Конфиг валидации JWT, который придёт от Auth-API
var jwt = builder.Configuration.GetSection("AuthJwt");
var issuer = jwt["Issuer"];
var audience = jwt["Audience"];
var key = jwt["Key"]; // HS256. (Если у вас RSA/JWKS — см. комментарий ниже)

var tvp = new TokenValidationParameters
{
    ValidateIssuer = !string.IsNullOrWhiteSpace(issuer),
    ValidIssuer = issuer,
    ValidateAudience = !string.IsNullOrWhiteSpace(audience),
    ValidAudience = audience,
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key!)),
    ClockSkew = TimeSpan.FromMinutes(2)
};
builder.Services.AddSingleton(tvp);

// Базовый URL Auth-API
builder.Services.Configure<AuthApiOptions>(builder.Configuration.GetSection("AuthApi"));



var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();


app.Run();


public sealed class AuthApiOptions
{
    public string BaseUrl { get; set; } = default!; // напр. "https://localhost:7001"
}
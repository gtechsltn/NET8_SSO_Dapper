# Single Sign On (SSO) in .NET 8

Mastering Single Sign-On (SSO) with .NET, SQL Server, and Dapper: A Complete Guide

https://medium.com/@hasanmcse/mastering-single-sign-on-sso-with-net-sql-server-and-dapper-a-complete-guide-39200e7c166b

## Procject 01: SSO Web API Development

Packages:
```
dotnet add package Dapper
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.IdentityModel.Tokens
dotnet add package Microsoft.Data.SqlClient
dotnet add package BCrypt.Net-Core --version 1.6.0
```

Create Database:
```
CREATE DATABASE SingleSignDB;

CREATE TABLE Users (
    Id INT PRIMARY KEY IDENTITY,
    Username NVARCHAR(50) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(255) NOT NULL
);
```

Add Connection String:
```
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=SingleSignDB;User Id=sa;Password=smicr@123;TrustServerCertificate=True;"
  }
}
```

Create User Model: models/User.cs
```
public class User
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string PasswordHash { get; set; }
}
```

Set Up Dapper Context: Data/DapperContext.cs
```
public interface IDapperContext
{
    IDbConnection CreateDbConnection();
}

public class DapperContext : IDapperContext
{
    private readonly IConfiguration _configuration;
    private readonly string _connectionString;

    public DapperContext(IConfiguration configuration)
    {
        _configuration = configuration;
        _connectionString = _configuration.GetConnectionString("DefaultConnection");
    }

    public IDbConnection CreateDbConnection()
    {
        return new SqlConnection(_connectionString);
    }
}
```

Create User Interface : Contacts/IUserRepository.cs
```
public interface IUserRepository
 {
     Task<int> CreateUserAsync(User user);
     Task<User> GetUserByUsernameAsync(string username);
 }
```

Create User Repository: Services/UserRepository.cs
```
public class UserRepository : IUserRepository
{
    private readonly IDapperContext _connection;

    public UserRepository(IDapperContext connection)
    {
        _connection = connection;
    }

    public async Task<User> GetUserByUsernameAsync(string username)
    {
        using var connection = _connection.CreateDbConnection();
        var query = "SELECT * FROM Users WHERE Username = @Username";
        return await connection.QuerySingleOrDefaultAsync<User>(query, new { Username = username });
    }

    public async Task<int> CreateUserAsync(User user)
    {
        using var connection = _connection.CreateDbConnection();
        var query = "INSERT INTO Users (Username, PasswordHash) VALUES (@Username, @PasswordHash); SELECT CAST(SCOPE_IDENTITY() as int);";
        return await connection.ExecuteScalarAsync<int>(query, user);
    }
}
```

Create a controller for user authentication:
```
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IUserRepository _userRepository;
    private readonly IConfiguration _configuration;

    public AuthController(IUserRepository userRepository, IConfiguration configuration)
    {
        _userRepository = userRepository;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] User user)
    {
        // Hash password (use a proper hashing algorithm like BCrypt)
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(user.PasswordHash);
        var userId = await _userRepository.CreateUserAsync(user);
        return CreatedAtAction(nameof(Register), new { id = userId }, user);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] User user)
    {
        var dbUser = await _userRepository.GetUserByUsernameAsync(user.Username);
        if (dbUser == null || !BCrypt.Net.BCrypt.Verify(user.PasswordHash, dbUser.PasswordHash))
        {
            return Unauthorized();
        }

        // Generate JWT token
        var token = GenerateJwtToken(dbUser);
        return Ok(new { Token = token });
    }

    private string GenerateJwtToken(User user)
    {
        var claims = new[]
        {
        new Claim(JwtRegisteredClaimNames.Sub, user.Username),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Issuer"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
```

Configure JWT Authentication in program.cs
```
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using SsoWebApi.Contacts;
using SsoWebApi.Data;
using SsoWebApi.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

//var Configuration = builder.Configuration();

// Add services to the container.
builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(x =>
    {
        x.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Issuer"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddScoped<IDapperContext, DapperContext>();
builder.Services.AddScoped<IUserRepository,UserRepository>();
builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    // Add JWT Authentication configuration to Swagger
    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter 'Bearer' [space] and then your valid token in the text input below.\r\n\r\nExample: \"Bearer abcdef12345\""
    });

    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
```

## Procject 02: SSO Web Admin Panel

Packages:
```
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.Extensions.Http
dotnet add package Microsoft.AspNetCore.Session
```

User Registration and Login Models
```
public class UserRegistrationModel
{
    public string Email { get; set; }
    public string Password { get; set; }
}

public class UserLoginModel
{
    public string Email { get; set; }
    public string Password { get; set; }
}
```

Create a interface for API Calls
```
public interface IAuthService
 {
     Task<string> LoginAsync(UserLoginModel model);
     Task<string> RegisterAsync(UserRegistrationModel model);
 }
```

Create a Service for API Calls
```
public class AuthService : IAuthService
{
    private readonly HttpClient _httpClient;

    public AuthService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<string> RegisterAsync(UserRegistrationModel model)
    {
        var response = await _httpClient.PostAsJsonAsync("api/auth/register", model);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync();
    }

    public async Task<string> LoginAsync(UserLoginModel model)
    {
        var response = await _httpClient.PostAsJsonAsync("api/auth/login", model);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync();
    }
}
```

Create an AuthController
```
public class AuthController : Controller
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpGet]
    public IActionResult Register() => View();

    [HttpPost]
    public async Task<IActionResult> Register(UserRegistrationModel model)
    {
        if (ModelState.IsValid)
        {
            await _authService.RegisterAsync(model);
            return RedirectToAction("Login");
        }

        return View(model);
    }

    [HttpGet]
    public IActionResult Login() => View();

    [HttpPost]
    public async Task<IActionResult> Login(UserLoginModel model)
    {
        if (ModelState.IsValid)
        {
            var token = await _authService.LoginAsync(model);
            // Store the token in session or local storage as required
            return RedirectToAction("Index", "Home");
        }

        return View(model);
    }
}
```

Create Register View
```
@model UserRegistrationModel

<h2>Register</h2>
<form asp-action="Register" method="post">
    <div>
        <label>Email</label>
        <input type="email" asp-for="Email" required />
    </div>
    <div>
        <label>Password</label>
        <input type="password" asp-for="Password" required />
    </div>
    <button type="submit">Register</button>
</form>
<a href="@Url.Action("Login", "Auth")">Already have an account? Login</a>
```

Create Login View
```
@model UserLoginModel

<h2>Login</h2>
<form asp-action="Login" method="post">
    <div>
        <label>Email</label>
        <input type="email" asp-for="Email" required />
    </div>
    <div>
        <label>Password</label>
        <input type="password" asp-for="Password" required />
    </div>
    <button type="submit">Login</button>
</form>
<a href="@Url.Action("Register", "Auth")">Don't have an account? Register</a>
```

Add HttpClient and Configure Dependency Injection
```
using SsoWebApp.Contacts;
using SsoWebApp.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
// Add session services
builder.Services.AddDistributedMemoryCache(); // Enables session state in memory
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Set session timeout
    options.Cookie.HttpOnly = true; // Set the cookie to be HttpOnly
    options.Cookie.IsEssential = true; // Make the session cookie essential
});

builder.Services.AddHttpClient<IAuthService,AuthService>(client =>
{
    client.BaseAddress = new Uri(builder.Configuration["APIs:AuthUrl"]); // Your API URL
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseSession(); // Enable session middleware

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Auth}/{action=Login}/{id?}");

app.Run();
```

Run the MVC Application

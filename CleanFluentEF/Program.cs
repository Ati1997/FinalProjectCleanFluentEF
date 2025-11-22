using CleanFluentEF.Models;
using CleanFluentEF.Services;
using CleanFluentEF.Models.DomainModels.PersonAggregates;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Identity;
using System.Text;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------
// AppSettings: Jwt section must exist in appsettings.json
// -----------------------------
var jwtSettings = builder.Configuration.GetSection("Jwt");
if (string.IsNullOrWhiteSpace(jwtSettings["Key"]))
{
    throw new Exception("Jwt:Key is not configured in appsettings.json");
}

// -----------------------------
// Add services to container
// -----------------------------
builder.Services.AddControllers();

// DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("Default"))
);

// PasswordHasher for User
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();

// DataSeeder
builder.Services.AddScoped<DataSeeder>();

// JWT Authentication
var key = Encoding.UTF8.GetBytes(jwtSettings["Key"]);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})


.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidateAudience = true,
        ValidAudience = jwtSettings["Audience"],
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30),

        RoleClaimType = "http://schemas.microsoft.com/microsoft/2008/06/identity/claims/role"
    };



    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = ctx =>
        {
            Console.WriteLine("JWT Failed: " + ctx.Exception?.Message);
            return Task.CompletedTask;
        },
        OnMessageReceived = ctx =>
        {
            var token = ctx.Request.Headers["Authorization"].ToString();
            Console.WriteLine("AUTH HEADER: " + token);
            return Task.CompletedTask;
        },
        OnTokenValidated = ctx =>
        {
            Console.WriteLine("JWT VALID! User: " + ctx.Principal.Identity.Name);
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization();

// Swagger + JWT support
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "CleanFluentEF API", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,     
        Scheme = "bearer",                  
        BearerFormat = "JWT"
    });


    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme {
                Reference = new OpenApiReference {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] { }
        }
    });
});

var app = builder.Build();

// -----------------------------
// Seed Roles & Admin User (run once at startup)
// -----------------------------
using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<DataSeeder>();
    // top-level await allowed in .NET 6+ Program.cs, otherwise use GetAwaiter().GetResult()
    await seeder.SeedAsync();
}

// -----------------------------
// HTTP pipeline
// -----------------------------
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

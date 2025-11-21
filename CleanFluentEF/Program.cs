using CleanFluentEF.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------
// Add services to the container
// -----------------------------
builder.Services.AddControllers();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("Default"))
);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "CleanFluentEF API", Version = "v1" });
});

// -----------------------------
// Build the app
// -----------------------------
var app = builder.Build();

// -----------------------------
// Configure the HTTP request pipeline
// -----------------------------
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();       // JSON OpenAPI
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "CleanFluentEF API v1");
    });
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();

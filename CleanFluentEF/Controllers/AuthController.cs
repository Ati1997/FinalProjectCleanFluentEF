using CleanFluentEF.Models.DomainModels.PersonAggregates;
using CleanFluentEF.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;


namespace CleanFluentEF.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _db;
        private readonly IPasswordHasher<User> _passwordHasher;
        private readonly IConfiguration _config;

        public AuthController(ApplicationDbContext db, IPasswordHasher<User> passwordHasher, IConfiguration config)
        {
            _db = db;
            _passwordHasher = passwordHasher;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            if (string.IsNullOrWhiteSpace(dto.UserName) || string.IsNullOrWhiteSpace(dto.Password))
                return BadRequest("Username and password required.");

            if (await _db.Set<User>().AnyAsync(u => u.FName == dto.UserName))
                return BadRequest("User already exists.");

            var user = new User
            {
                Id = Guid.NewGuid(),
                FName = dto.UserName,
                LName = dto.DisplayName ?? dto.UserName
            };

            user.PasswordHash = _passwordHasher.HashPassword(user, dto.Password);

            if (dto.Roles != null && dto.Roles.Any())
            {
                var roles = await _db.Set<Role>().Where(r => dto.Roles.Contains(r.FName)).ToListAsync();
                user.Roles = roles;
            }

            _db.Set<User>().Add(user);
            await _db.SaveChangesAsync();

            return Ok(new { user.Id, user.FName });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            if (string.IsNullOrWhiteSpace(dto.UserName) || string.IsNullOrWhiteSpace(dto.Password))
                return BadRequest("Username and password required.");

            var user = await _db.Set<User>()
                .Include(u => u.Roles)
                .FirstOrDefaultAsync(u => u.FName == dto.UserName);

            if (user == null) return Unauthorized();

            var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash ?? string.Empty, dto.Password);
            if (result == PasswordVerificationResult.Failed) return Unauthorized();

            var token = GenerateToken(user);
            return Ok(new { token });
        }

        private string GenerateToken(User user)
        {
            var jwtSection = _config.GetSection("Jwt");
            var key = Encoding.UTF8.GetBytes(jwtSection["Key"]);
            var issuer = jwtSection["Issuer"];
            var audience = jwtSection["Audience"];
            var expiresMinutes = int.Parse(jwtSection["ExpiresInMinutes"] ?? "60");

            var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.FName)
    };

            // ✔ نقش‌ها در فرمت صحیح برای Authorize(Roles="Administrator")
            if (user.Roles != null)
            {
                foreach (var r in user.Roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, r.FName));
                }
            }

            var creds = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expiresMinutes),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


    }

    // DTOs
    public class RegisterDto
    {
        public string UserName { get; set; } = null!;
        public string Password { get; set; } = null!;
        public string? DisplayName { get; set; }
        public List<string>? Roles { get; set; }
    }

    public class LoginDto
    {
        public string UserName { get; set; } = null!;
        public string Password { get; set; } = null!;
    }
}

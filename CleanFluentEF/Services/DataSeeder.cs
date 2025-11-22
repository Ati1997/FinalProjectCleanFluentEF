using CleanFluentEF.Models.DomainModels.PersonAggregates;
using CleanFluentEF.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace CleanFluentEF.Services
{
    public class DataSeeder
    {
        private readonly ApplicationDbContext _db;
        private readonly IPasswordHasher<User> _passwordHasher;

        public DataSeeder(ApplicationDbContext db, IPasswordHasher<User> passwordHasher)
        {
            _db = db;
            _passwordHasher = passwordHasher;
        }

        public async Task SeedAsync()
        {
            // apply pending migrations
            await _db.Database.MigrateAsync();

            // seed roles
            var roles = new[] { "Administrator", "NormalAdmin", "User" };
            foreach (var roleName in roles)
            {
                if (!await _db.Set<Role>().AnyAsync(r => r.FName == roleName))
                {
                    _db.Set<Role>().Add(new Role { Id = Guid.NewGuid(), FName = roleName });
                }
            }

            await _db.SaveChangesAsync();

            // seed admin user
            var adminUserName = "sysadmin";
            var admin = await _db.Set<User>()
                .Include(u => u.Roles)
                .FirstOrDefaultAsync(u => u.FName == adminUserName);

            if (admin == null)
            {
                admin = new User
                {
                    Id = Guid.NewGuid(),
                    FName = adminUserName,
                    LName = "Administrator",
                    Roles = new List<Role>()
                };

                admin.PasswordHash = _passwordHasher.HashPassword(admin, "P@ssw0rd!");

                var adminRole = await _db.Set<Role>().FirstAsync(r => r.FName == "Administrator");
                admin.Roles = new List<Role> { adminRole };

                _db.Set<User>().Add(admin);
                await _db.SaveChangesAsync();
            }
        }
    }
}

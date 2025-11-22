using Microsoft.EntityFrameworkCore;
using System.Reflection;
using CleanFluentEF.Models.Frameworks;

namespace CleanFluentEF.Models
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

       
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Apply all Fluent API configurations
            modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());

            // Register all entities automatically
            modelBuilder.RegisterAllEntities<IDbSetEntity>(typeof(IDbSetEntity).Assembly);

            base.OnModelCreating(modelBuilder);
        }
    }
}

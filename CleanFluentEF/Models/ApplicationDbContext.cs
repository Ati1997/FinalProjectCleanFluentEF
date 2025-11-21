using CleanFluentEF.Models.DomainModels.OrderAggregates;
using CleanFluentEF.Models.DomainModels.PersonAggregates;
using CleanFluentEF.Models.DomainModels.ProductAggregates;
using CleanFluentEF.Models.Frameworks;
using Microsoft.EntityFrameworkCore;
using System.Reflection;

namespace CleanFluentEF.Models
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        #region [- OnModelCreating -]
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // رجیستر همه کلاس‌های IEntityTypeConfiguration<T>
            modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());

            base.OnModelCreating(modelBuilder);
        }
        #endregion

        #region [- DbSets -]
        public DbSet<Product> Products => Set<Product>();
        public DbSet<Category> Categories => Set<Category>();

        public DbSet<User> Users => Set<User>();
        public DbSet<Role> Roles => Set<Role>();
        public DbSet<Person> Persons => Set<Person>();
        public DbSet<Employee> Employees => Set<Employee>();

        public DbSet<OrderHeader> OrderHeaders => Set<OrderHeader>();
        public DbSet<OrderDetail> OrderDetails => Set<OrderDetail>();

        #endregion
    }
}

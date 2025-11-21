using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;
using CleanFluentEF.Models.DomainModels.PersonAggregates;

namespace CleanFluentEF.Models.Configurations
{
    public class UserConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            builder.ToTable("UsersTable", "Person");
            builder.HasKey(u => u.Id);

            builder.Property(u => u.FName)
                .IsRequired()
                .HasMaxLength(50);

            builder.Property(u => u.LName)
                .IsRequired()
                .HasMaxLength(50);

            // Many-to-Many (Final Standard Version)
            builder
                .HasMany(u => u.Roles)
                .WithMany(r => r.Users)
                .UsingEntity<Dictionary<string, object>>(
                    "UserRoleMapping", // Table name
                    join => join
                        .HasOne<Role>()
                        .WithMany()
                        .HasForeignKey("RoleId")
                        .OnDelete(DeleteBehavior.Cascade),

                    join => join
                        .HasOne<User>()
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade),

                    join =>
                    {
                        join.ToTable("UserRoleMapping", "Person"); // 👈 مهم‌ترین بخش
                    }
                );
        }
    }
}

using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;
using CleanFluentEF.Models.DomainModels.PersonAggregates;

namespace CleanFluentEF.Models.Configurations
{
    public class RoleConfiguration : IEntityTypeConfiguration<Role>
    {
        public void Configure(EntityTypeBuilder<Role> builder)
        {
            builder.ToTable("Roles", "Person");

            builder.HasKey(r => r.Id);

            builder.Property(r => r.FName)
                .IsRequired()
                .HasMaxLength(50);
        }
    }
}

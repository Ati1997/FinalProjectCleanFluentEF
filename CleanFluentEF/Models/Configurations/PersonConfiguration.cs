using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;
using CleanFluentEF.Models.DomainModels.PersonAggregates;

namespace CleanFluentEF.Models.Configurations
{
    public class PersonConfiguration : IEntityTypeConfiguration<Person>
    {
        public void Configure(EntityTypeBuilder<Person> builder)
        {
            builder.ToTable("Persons", "Person");

            builder.HasKey(p => p.Id);

            builder.Property(p => p.FName)
                .IsRequired()
                .HasMaxLength(50);

            builder.Property(p => p.LName)
                .IsRequired()
                .HasMaxLength(50);
        }
    }
}

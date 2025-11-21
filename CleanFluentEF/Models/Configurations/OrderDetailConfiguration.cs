using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;
using CleanFluentEF.Models.DomainModels.OrderAggregates;

namespace CleanFluentEF.Models.Configurations
{
    public class OrderDetailConfiguration : IEntityTypeConfiguration<OrderDetail>
    {
        public void Configure(EntityTypeBuilder<OrderDetail> builder)
        {
            builder.ToTable("OrderDetails", "Orders");

            builder.HasKey(od => new { od.OrderHeaderId, od.ProductId });

            builder.HasOne(od => od.OrderHeader)
                .WithMany(oh => oh.OrderDetails)
                .HasForeignKey(od => od.OrderHeaderId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(od => od.Product)
                .WithMany()
                .HasForeignKey(od => od.ProductId)
                .OnDelete(DeleteBehavior.Restrict);

            builder.Property(od => od.UnitPrice)
                .HasPrecision(18, 2);

            builder.Property(od => od.Quantity)
                .IsRequired();
        }
    }
}

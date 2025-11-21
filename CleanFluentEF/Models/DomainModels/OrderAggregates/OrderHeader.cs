using CleanFluentEF.Models.DomainModels.PersonAggregates;
using CleanFluentEF.Models.Frameworks;

namespace CleanFluentEF.Models.DomainModels.OrderAggregates
{
    public class OrderHeader : IDbSetEntity
    {
        public Guid Id { get; set; }

        public Guid SellerId { get; set; }
        public Person Seller { get; set; } = null!;

        public Guid BuyerId { get; set; }
        public Person Buyer { get; set; } = null!;

        public List<OrderDetail>? OrderDetails { get; set; }
    }
}

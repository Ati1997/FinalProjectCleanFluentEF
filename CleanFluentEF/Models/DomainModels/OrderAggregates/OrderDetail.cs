using CleanFluentEF.Models.DomainModels.ProductAggregates;
using CleanFluentEF.Models.Frameworks;

namespace CleanFluentEF.Models.DomainModels.OrderAggregates
{
    public class OrderDetail : IDbSetEntity
    {
        public Guid OrderHeaderId { get; set; }
        public OrderHeader OrderHeader { get; set; }

        public Guid ProductId { get; set; }
        public Product Product { get; set; }

        public decimal UnitPrice { get; set; }
        public int Quantity { get; set; }
    }
}

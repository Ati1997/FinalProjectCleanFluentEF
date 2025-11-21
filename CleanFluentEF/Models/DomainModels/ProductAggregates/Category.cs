using CleanFluentEF.Models.Frameworks;

namespace CleanFluentEF.Models.DomainModels.ProductAggregates
{
    public class Category : IDbSetEntity
    {
        public Guid Id { get; set; }
        public string Title { get; set; }
        public List<Product>? Products { get; set; } // Navigation
    }
}

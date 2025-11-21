using CleanFluentEF.Models.Frameworks;

namespace CleanFluentEF.Models.DomainModels.ProductAggregates
{
    public class Product : IDbSetEntity
    {
        public Guid Id { get; set; }
        public string Title { get; set; }
        public decimal UnitPrice { get; set; }
        public DateTime DateCreation { get; set; }
        public DateTime DateModification { get; set; }
        public bool IsDeleted { get; set; }

        public Guid CategoryId { get; set; } // Foreign Key
        public Category? Category { get; set; } // Navigation
    }
}

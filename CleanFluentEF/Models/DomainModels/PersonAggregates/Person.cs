using CleanFluentEF.Models.Frameworks;

namespace CleanFluentEF.Models.DomainModels.PersonAggregates
{
    public class Person : IDbSetEntity
    {
        public Guid Id { get; set; }
        public string FName { get; set; }
        public string LName { get; set; }
    }
}

using CleanFluentEF.Models.Frameworks;

namespace CleanFluentEF.Models.DomainModels.PersonAggregates
{
    public class Role : IDbSetEntity
    {
        public Guid Id { get; set; }
        public string FName { get; set; }
        public List<User> Users { get; set; }
    }
}

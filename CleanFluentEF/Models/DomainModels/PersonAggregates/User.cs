using CleanFluentEF.Models.Frameworks;

namespace CleanFluentEF.Models.DomainModels.PersonAggregates
{
    public class User : IDbSetEntity
    {
        public Guid Id { get; set; }
        public string FName { get; set; }
        public string LName { get; set; }
        public List<Role>? Roles { get; set; }
    }
}

using CleanFluentEF.Models.Frameworks;

namespace CleanFluentEF.Models.DomainModels.PersonAggregates
{
    public class User : IDbSetEntity
    {
        public Guid Id { get; set; }
        public string FName { get; set; } = null!; // we use as username for simplicity
        public string LName { get; set; } = null!;

        // PasswordHash for authentication
        public string? PasswordHash { get; set; }

        // Navigation
        public List<Role>? Roles { get; set; }
    }
}

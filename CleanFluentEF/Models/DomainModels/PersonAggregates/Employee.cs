using CleanFluentEF.Models.Frameworks;

namespace CleanFluentEF.Models.DomainModels.PersonAggregates
{
    public class Employee : IDbSetEntity
    {
        public Guid Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateTime BirthDate { get; set; }
        public string Address { get; set; }
        public int EmployeeCode { get; set; }
        public string Title { get; set; }
        public decimal Salary { get; set; }
    }
}

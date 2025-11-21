using Microsoft.EntityFrameworkCore;
using System.Reflection;

namespace CleanFluentEF.Models.Frameworks
{
    public static class ModelBuilderExtensions
    {
        public static void RegisterAllEntities<TInterface>(this ModelBuilder modelBuilder, params Assembly[] assemblies)
        {
            var types = assemblies
                .SelectMany(a => a.GetExportedTypes())
                .Where(c => c.IsClass && !c.IsAbstract && typeof(TInterface).IsAssignableFrom(c));

            foreach (var type in types)
            {
                modelBuilder.Entity(type);
            }
        }
    }
}

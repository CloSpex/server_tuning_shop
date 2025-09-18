using Microsoft.EntityFrameworkCore;
using TuningStore.Models;

namespace TuningStore.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }
        public DbSet<User> Users => Set<User>();
        public DbSet<Brand> Brands => Set<Brand>();

        public DbSet<Model> Models => Set<Model>();
        public DbSet<Specification> Specifications => Set<Specification>();
        public DbSet<EngineType> EngineTypes => Set<EngineType>();
        public DbSet<TransmissionType> TransmissionTypes => Set<TransmissionType>();
        public DbSet<BodyType> BodyTypes => Set<BodyType>();

    }
}
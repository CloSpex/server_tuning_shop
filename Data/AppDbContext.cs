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
        public DbSet<Part> Parts => Set<Part>();
        public DbSet<PartCategory> PartCategories => Set<PartCategory>();
        public DbSet<FAQ> FAQs => Set<FAQ>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<User>()
                .HasIndex(u => u.Username)
                .IsUnique();

            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique();

            modelBuilder.Entity<Brand>()
                .HasIndex(b => b.Name)
                .IsUnique();

            modelBuilder.Entity<Model>()
                .HasIndex(m => m.Name)
                .IsUnique();

            modelBuilder.Entity<Part>()
                .HasIndex(p => new { p.Name, p.CarSpecificationId, p.Color })
                .IsUnique();


            modelBuilder.Entity<Brand>()
                .HasMany(b => b.Models)
                .WithOne(m => m.Brand)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<Model>()
                .HasMany(m => m.Specifications)
                .WithOne(s => s.Model)
                .OnDelete(DeleteBehavior.Restrict);
        }
    }
}

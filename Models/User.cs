using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TuningStore.Models
{
    [Table("Users")]
    public class User : BaseModel
    {

        [Required]
        [Column("username")]
        [StringLength(255, MinimumLength = 3)]
        public string Username { get; set; } = string.Empty;

        [Required]
        [Column("email")]
        [EmailAddress]
        [StringLength(255)]
        public string Email { get; set; } = string.Empty;

        [Required]
        [Column("password")]
        [StringLength(255)]
        public string Password { get; set; } = string.Empty;

        [Column("role")]
        [StringLength(50)]
        public string? Role { get; set; } = "User";

        public List<RefreshToken> RefreshTokens { get; set; } = new();
    }
}
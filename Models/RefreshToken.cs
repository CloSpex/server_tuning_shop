using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace TuningStore.Models
{
    [Table("RefreshTokens")]
    public class RefreshToken
    {
        [Key]
        [Column("id")]
        public int Id { get; set; }

        [Required]
        [Column("user_id")]
        public int UserId { get; set; }

        [Required]
        [Column("token")]
        [StringLength(500)]
        public string Token { get; set; } = string.Empty;

        [Required]
        [Column("expires_at")]
        public DateTime ExpiresAt { get; set; }

        [Required]
        [Column("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [Column("revoked_at")]
        public DateTime? RevokedAt { get; set; }

        [Column("revoked_by_ip")]
        [StringLength(45)]
        public string? RevokedByIp { get; set; }

        [Column("replaced_by_token")]
        [StringLength(500)]
        public string? ReplacedByToken { get; set; }

        [Column("created_by_ip")]
        [StringLength(45)]
        public string? CreatedByIp { get; set; }

        [ForeignKey(nameof(UserId))]
        public User User { get; set; } = null!;

        [NotMapped]
        public bool IsExpired => DateTime.UtcNow >= ExpiresAt;

        [NotMapped]
        public bool IsRevoked => RevokedAt != null;

        [NotMapped]
        public bool IsActive => !IsRevoked && !IsExpired;
    }
}
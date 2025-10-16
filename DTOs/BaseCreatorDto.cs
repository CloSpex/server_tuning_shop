using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using TuningStore.Models;
namespace TuningStore.DTOs
{
    public abstract class BaseCreatorDto : BaseDto
    {

        public int? CreatedBy { get; set; }
        public int? UpdatedBy { get; set; }
    }
}
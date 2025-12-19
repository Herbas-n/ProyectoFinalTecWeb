using System.ComponentModel.DataAnnotations;

namespace ProyectoFinalTecWeb.Entities.Dtos.Auth
{
    public class ForgotPasswordDto
    {
        [Required, EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string UserType { get; set; } = string.Empty; // "Passenger" or "Driver"
    }
}

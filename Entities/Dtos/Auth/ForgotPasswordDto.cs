namespace ProyectoFinalTecWeb.Entities.Dtos.Auth
{
    public class ForgotPasswordDto
    {
        public string Email { get; init; } = string.Empty;
    }

    public class ForgotToken
    {
        public required string RefreshToken { get; set; }
    }

    public class ResetPasswordRequestDto
    {
        public required string RefreshToken { get; set; }
        public string Password { get; init; } = string.Empty;
    }
    
}

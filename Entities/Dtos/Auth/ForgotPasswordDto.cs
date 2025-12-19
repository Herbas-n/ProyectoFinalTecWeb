namespace ProyectoFinalTecWeb.Entities.Dtos.Auth
{
    public class ForgotPasswordDto
    {
        public string Email { get; init; } = string.Empty;
    }

    public class ForgotToken
    {
        public required string AccessToken { get; set; }
    }
}

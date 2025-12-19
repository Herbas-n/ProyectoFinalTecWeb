namespace ProyectoFinalTecWeb.Entities.Dtos.Auth
{
   public class ForgotPasswordDto
    {
        public string Email { get; set; }
    }
   public class RsetPasswordDto
    {
        public int Token { get; set; }
        public string NewPassword { get; set; }
    }

}

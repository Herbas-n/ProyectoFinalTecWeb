
using ProyectoFinalTecWeb.Entities.Dtos.Auth;
using ProyectoFinalTecWeb.Entities.Dtos.DriverDto;
using ProyectoFinalTecWeb.Entities.Dtos.PassengerDto;
using ProyectoFinalTecWeb.Repositories;

using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using ProyectoFinalTecWeb.Entities;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ProyectoFinalTecWeb.Services
{
    public class AuthService : IAuthService
    {
        private readonly IDriverRepository _drivers;
        private readonly IPassengerRepository _passengers;
        private readonly IConfiguration _configuration;

        public AuthService(IDriverRepository drivers, IPassengerRepository passengers, IConfiguration configuration)
        {
            _drivers = drivers;
            _passengers = passengers;
            _configuration = configuration;
        }

        public async Task<(bool ok, LoginResponseDto? response)> LoginAsync(LoginDto dto)
        {
            // Primero buscar driver
            var driver = await _drivers.GetByEmailAddress(dto.Email);
            if (driver != null)
            {
                var ok = BCrypt.Net.BCrypt.Verify(dto.Password, driver.PasswordHash);
                if (!ok) return (false, null);

                // Generar par access/refresh
                var (accessToken, expiresIn, jti) = GenerateJwtTokenD(driver);
                var refreshToken = GenerateSecureRefreshToken();

                var refreshDays = int.Parse(_configuration["Jwt:RefreshDays"] ?? "14");

                driver.RefreshToken = refreshToken;
                driver.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(refreshDays);
                driver.RefreshTokenRevokedAt = null;
                driver.CurrentJwtId = jti;
                await _drivers.Update(driver);

                var resp = new LoginResponseDto
                {
                    User = new UserDto { Id = driver.Id, Name = driver.Name, Email = driver.Email },
                    Role = driver.Role,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = expiresIn,
                    TokenType = "Bearer"
                };

                return (true, resp);
            }

            // Si no es driver, buscar passenger
            var passenger = await _passengers.GetByEmailAddress(dto.Email);
            if (passenger != null)
            {
                var ok = BCrypt.Net.BCrypt.Verify(dto.Password, passenger.PasswordHash);
                if (!ok) return (false, null);

                // Generar par access/refresh
                var (accessToken, expiresIn, jti) = GenerateJwtTokenP(passenger);
                var refreshToken = GenerateSecureRefreshToken();

                var refreshDays = int.Parse(_configuration["Jwt:RefreshDays"] ?? "14");

                passenger.RefreshToken = refreshToken;
                passenger.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(refreshDays);
                passenger.RefreshTokenRevokedAt = null;
                passenger.CurrentJwtId = jti;
                await _passengers.Update(passenger);

                var resp = new LoginResponseDto
                {
                    User = new UserDto { Id = passenger.Id, Name = passenger.Name, Email = passenger.Email },
                    Role = passenger.Role,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = expiresIn,
                    TokenType = "Bearer"
                };

                return (true, resp);
            }

            // Si no es ni driver ni passenger
            return (false, null);
        }

        public async Task<(bool ok, LoginResponseDto? response)> RefreshAsync(RefreshRequestDto dto)
        {
            // Buscar driver con el refresh token
            var driver = await _drivers.GetByRefreshToken(dto.RefreshToken);
            if (driver != null)
            {
                // Validaciones de refresh
                if (driver.RefreshToken != dto.RefreshToken) return (false, null);
                if (driver.RefreshTokenRevokedAt.HasValue) return (false, null);
                if (!driver.RefreshTokenExpiresAt.HasValue || driver.RefreshTokenExpiresAt.Value < DateTime.UtcNow) return (false, null);

                // Rotación: generar nuevo access + refresh y revocar el anterior
                var (accessToken, expiresIn, jti) = GenerateJwtTokenD(driver);
                var newRefresh = GenerateSecureRefreshToken();
                var refreshDays = int.Parse(_configuration["Jwt:RefreshDays"] ?? "14");

                driver.RefreshToken = newRefresh;
                driver.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(refreshDays);
                driver.RefreshTokenRevokedAt = null; // seguimos activo
                driver.CurrentJwtId = jti;
                await _drivers.Update(driver);

                var resp = new LoginResponseDto
                {
                    User = new UserDto { Id = driver.Id, Name = driver.Name, Email = driver.Email },
                    Role = driver.Role,
                    AccessToken = accessToken,
                    RefreshToken = newRefresh,
                    ExpiresIn = expiresIn,
                    TokenType = "Bearer"
                };

                return (true, resp);
            }

            // Buscar passenger con el refresh token
            var passenger = await _passengers.GetByRefreshToken(dto.RefreshToken);
            if (passenger != null)
            {
                // Validaciones de refresh
                if (passenger.RefreshToken != dto.RefreshToken) return (false, null);
                if (passenger.RefreshTokenRevokedAt.HasValue) return (false, null);
                if (!passenger.RefreshTokenExpiresAt.HasValue || passenger.RefreshTokenExpiresAt.Value < DateTime.UtcNow) return (false, null);

                // Rotación: generar nuevo access + refresh y revocar el anterior
                var (accessToken, expiresIn, jti) = GenerateJwtTokenP(passenger);
                var newRefresh = GenerateSecureRefreshToken();
                var refreshDays = int.Parse(_configuration["Jwt:RefreshDays"] ?? "14");

                passenger.RefreshToken = newRefresh;
                passenger.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(refreshDays);
                passenger.RefreshTokenRevokedAt = null;
                passenger.CurrentJwtId = jti;
                await _passengers.Update(passenger);

                var resp = new LoginResponseDto
                {
                    User = new UserDto { Id = passenger.Id, Name = passenger.Name, Email = passenger.Email },
                    Role = passenger.Role,
                    AccessToken = accessToken,
                    RefreshToken = newRefresh,
                    ExpiresIn = expiresIn,
                    TokenType = "Bearer"
                };

                return (true, resp);
            }

            return (false, null);
        }

        public async Task<string> RegisterDriverAsync(RegisterDriverDto dto)
        {
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(dto.Password);
            var driver = new Driver
            {
                Email = dto.Email,
                PasswordHash = hashedPassword,
                Name = dto.Name,
                Role = dto.Role,
                Licence = dto.Licence,
                Phone = dto.Phone
            };
            await _drivers.AddAsync(ddriver);
            return driver.Id.ToString();
        }

        public async Task<string> RegisterPassengerAsync(RegisterPassengerDto dto)
        {
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(dto.Password);
            var passenger = new Passenger
            {
                Email = dto.Email,
                PasswordHash = hashedPassword,
                Name = dto.Name,
                Phone = dto.Phone,
                Role = dto.Role
            };
            await _passengers.AddAsync(passenger);
            return passenger.Id.ToString();
        }

        //Generar token para reset password
        public async Task<string> GeneratePasswordResetToken(ForgotPasswordDto dto)
        {
            // Generar token basado en minutos actuales (hora * 60 + minutos)
            var token = (DateTime.UtcNow.Hour * 60 + DateTime.UtcNow.Minute).ToString();

            // Hashear el token para almacenarlo de forma segura
            using var sha256 = SHA256.Create();
            var hashedToken = Convert.ToHexString(
                sha256.ComputeHash(Encoding.UTF8.GetBytes(token)));

            if (dto.UserType.ToLower() == "driver")
            {
                var driver = await _drivers.GetByEmailAddress(dto.Email);
                if (driver == null)
                    throw new Exception("Driver no encontrado con ese email");

                // Guardar token hasheado y fecha de expiración
                driver.ResetPasswordToken = hashedToken;
                driver.ResetPasswordTokenExpiresAt = DateTime.UtcNow.AddMinutes(15); // 15 minutos de validez

                await _drivers.Update(driver);
            }
            else if (dto.UserType.ToLower() == "passenger")
            {
                var passenger = await _passengers.GetByEmailAddress(dto.Email);
                if (passenger == null)
                    throw new Exception("Passenger no encontrado con ese email");

                passenger.ResetPasswordToken = hashedToken;
                passenger.ResetPasswordTokenExpiresAt = DateTime.UtcNow.AddMinutes(15);

                await _passengers.Update(passenger);
            }
            else
            {
                throw new Exception("Tipo de usuario inválido. Use 'driver' o 'passenger'");
            }

            // Retornar el token en texto plano para el usuario
            return token;
        }

        // Resetear password con token
        public async Task<bool> ResetPassword(ResetPasswordDto dto)
        {
            // Hashear el token recibido para compararlo con el almacenado
            using var sha256 = SHA256.Create();
            var hashedToken = Convert.ToHexString(
                sha256.ComputeHash(Encoding.UTF8.GetBytes(dto.Token)));

            if (dto.UserType.ToLower() == "driver")
            {
                // Buscar driver con token válido (que no esté expirado)
                var driver = await _drivers.GetByResetToken(hashedToken);
                if (driver == null ||
                    !driver.ResetPasswordTokenExpiresAt.HasValue ||
                    driver.ResetPasswordTokenExpiresAt.Value < DateTime.UtcNow)
                    throw new Exception("Token inválido o expirado");

                // Hashear nueva contraseña con BCrypt (igual que en registro)
                var newPasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);

                // Actualizar password y limpiar token
                driver.PasswordHash = newPasswordHash;
                driver.ResetPasswordToken = null;
                driver.ResetPasswordTokenExpiresAt = null;

                await _drivers.Update(driver);
            }
            else if (dto.UserType.ToLower() == "passenger")
            {
                var passenger = await _passengers.GetByResetToken(hashedToken);
                if (passenger == null ||
                    !passenger.ResetPasswordTokenExpiresAt.HasValue ||
                    passenger.ResetPasswordTokenExpiresAt.Value < DateTime.UtcNow)
                    throw new Exception("Token inválido o expirado");

                var newPasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);

                passenger.PasswordHash = newPasswordHash;
                passenger.ResetPasswordToken = null;
                passenger.ResetPasswordTokenExpiresAt = null;

                await _passengers.Update(passenger);
            }
            else
            {
                throw new Exception("Tipo de usuario inválido. Use 'driver' o 'passenger'");
            }

            return true;
        }

        private (string token, int expiresInSeconds, string jti) GenerateJwtTokenD(Driver driver)
        {
            var jwtSection = _configuration.GetSection("Jwt");
            var key = jwtSection["Key"]!;
            var issuer = jwtSection["Issuer"];
            var audience = jwtSection["Audience"];
            var expireMinutes = int.Parse(jwtSection["ExpiresMinutes"] ?? "60");

            var jti = Guid.NewGuid().ToString();

            var claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Sub, driver.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, driver.Email),
                new Claim(ClaimTypes.Name, driver.Name),
                new Claim(ClaimTypes.Role, driver.Role),
                new Claim(JwtRegisteredClaimNames.Jti, jti),
            };

            var keyBytes = Convert.FromBase64String(key);
            var creds = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);

            var expires = DateTime.UtcNow.AddMinutes(expireMinutes);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return (jwt, (int)TimeSpan.FromMinutes(expireMinutes).TotalSeconds, jti);
        }

        private (string token, int expiresInSeconds, string jti) GenerateJwtTokenP(Passenger passenger)
        {
            var jwtSection = _configuration.GetSection("Jwt");
            var key = jwtSection["Key"]!;
            var issuer = jwtSection["Issuer"];
            var audience = jwtSection["Audience"];
            var expireMinutes = int.Parse(jwtSection["ExpiresMinutes"] ?? "60");

            var jti = Guid.NewGuid().ToString();

            var claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Sub, passenger.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, passenger.Email),
                new Claim(ClaimTypes.Name, passenger.Name),
                new Claim(ClaimTypes.Role, passenger.Role),
                new Claim(JwtRegisteredClaimNames.Jti, jti),
            };

            var keyBytes = Convert.FromBase64String(key);
            var creds = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);

            var expires = DateTime.UtcNow.AddMinutes(expireMinutes);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return (jwt, (int)TimeSpan.FromMinutes(expireMinutes).TotalSeconds, jti);
        }

        private static string GenerateSecureRefreshToken()
        {
            // 64 bytes aleatorios en Base64Url
            var bytes = RandomNumberGenerator.GetBytes(64);
            return Base64UrlEncoder.Encode(bytes);
        }
    }
}
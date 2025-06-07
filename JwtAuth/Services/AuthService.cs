namespace JwtAuth.Services
{
    public interface IAuthService
    {
        Task<dynamic> login();
        Task<dynamic> register();
        Task<dynamic> logout();
        Task<dynamic> info();

    }
    public class AuthService : IAuthService
    {
        public async Task<dynamic> login()
        {
            // Logic for login
            return Task.FromResult<dynamic>(new { message = "Login successful" });
        }
        public async Task<dynamic> register()
        {
            // Logic for registration
            return Task.FromResult<dynamic>(new { message = "Registration successful" });
        }
        public async Task<dynamic> logout()
        {
            // Logic for logout
            return Task.FromResult<dynamic>(new { message = "Logout successful" });
        }
        public async Task<dynamic> info()
        {
            // Logic to get user info
            return Task.FromResult<dynamic>(new { message = "User info retrieved successfully" });
        }
    }
}

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost("login")]
        public IActionResult Login()
        {
            return View();
        }
        [HttpPost("register")]
        public IActionResult Register()
        {
            return View();
        }
        [HttpPost("logout")]
        public IActionResult Logout()
        {
            return View();
        }
        [HttpPost("info")]
        [Authorize]
        public IActionResult Info()
        {
            return View();
        }
        [HttpPost("testauth")]
        [Authorize]
        public IActionResult TestAuth()
        {
            // nếu đăng nhập rồi thì mới truy cập được, nếu chưa đăng nhập thì lỗi 401 Unauthorized
            return View();
        }
        [HttpGet("admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminOnly()
        {           
            return View();
        }
    }
}

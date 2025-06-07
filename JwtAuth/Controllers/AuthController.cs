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
        public IActionResult Login()
        {
            return View();
        }
        public IActionResult Register()
        {
            return View();
        }
        public IActionResult Logout()
        {
            return View();
        }
        public IActionResult Info()
        {
            return View();
        }
        [Authorize]
        public IActionResult TestAuth()
        {
            // nếu đăng nhập rồi thì mới truy cập được, nếu chưa đăng nhập thì lỗi 401 Unauthorized
            return View();
        }
    }
}

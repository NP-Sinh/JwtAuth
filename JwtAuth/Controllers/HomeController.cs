using System.Diagnostics;
using JwtAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtAuth.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                ViewBag.UserName = User.Identity.Name;
                ViewBag.UserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                ViewBag.IsAdmin = User.IsInRole("Admin");
            }
            return View();
        }

        [Authorize]
        public IActionResult Dashboard()
        {
            ViewBag.UserName = User.Identity?.Name;
            ViewBag.IsAdmin = User.IsInRole("Admin");
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}

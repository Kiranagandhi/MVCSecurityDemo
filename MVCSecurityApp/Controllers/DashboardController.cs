using MVCSecurityApp.Filters;
using System.Web.Mvc;

namespace MVCSecurityApp.Controllers
{
    [AuthenticateUser]
    public class DashboardController : Controller
    {
        // GET: Dashboard
        public ActionResult Index()
        {
            return View();
        }
    }
}
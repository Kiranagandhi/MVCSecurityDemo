using Microsoft.Security.Application;
using MVCSecurityApp.Filters;
using MVCSecurityApp.Models;
using System;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace MVCSecurityApp.Controllers
{
    [AuthenticateUser]
    public class HomeController : Controller
    {
        AllSecurityDBEntities dbcon = new AllSecurityDBEntities();

        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(EmployeeDetail EmployeeDetail)
        {
            if (ModelState.IsValid)
            {
                string demoAddress = Sanitizer.GetSafeHtmlFragment(EmployeeDetail.Address);
                dbcon.EmployeeDetails.Add(EmployeeDetail);
                dbcon.SaveChanges();
                return RedirectToAction("DisplayEmployee", "Home");
            }
            return View(EmployeeDetail);
        }

        public ActionResult DisplayEmployee()
        {
            return View(dbcon.EmployeeDetails.ToList());
        }
    }
}
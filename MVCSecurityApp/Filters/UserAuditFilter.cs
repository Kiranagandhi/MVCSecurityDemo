using MVCSecurityApp.Models;
using System;
using System.Web;
using System.Web.Mvc;

namespace MVCSecurityApp.Filters
{
    public class UserAuditFilter : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {

            string actionName = filterContext.ActionDescriptor.ActionName;
            string controllerName = filterContext.ActionDescriptor.ControllerDescriptor.ControllerName;
            var request = filterContext.HttpContext.Request;

            AuditTB objaudit = new AuditTB();

            if (HttpContext.Current.Session["UserID"] == null)
            {
                objaudit.UserID = 0;
            }
            else
            {
                objaudit.UserID = Convert.ToInt32(HttpContext.Current.Session["UserID"]);
            }
            objaudit.UsersAuditID = 0;
            objaudit.SessionID = HttpContext.Current.Session.SessionID;
            objaudit.IPAddress = request.ServerVariables["HTTP_X_FORWARDED_FOR"] ?? request.UserHostAddress;
            objaudit.PageAccessed = request.RawUrl;
            objaudit.LoggedInAt = DateTime.Now;
            if (actionName == "LogOff")
            {
                objaudit.LoggedOutAt = DateTime.Now;
            }

            objaudit.LoginStatus = "A";
            objaudit.ControllerName = controllerName;
            objaudit.ActionName = actionName;

            AllSecurityDBEntities context = new AllSecurityDBEntities();
            context.AuditTBs.Add(objaudit);
            context.SaveChanges();

            //Finishes executing the Action as normal 
            base.OnActionExecuting(filterContext);


        }
    }
}
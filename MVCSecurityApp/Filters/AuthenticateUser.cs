using System;
using System.Web.Mvc;

namespace MVCSecurityApp.Filters
{
    public class AuthenticateUser : FilterAttribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationContext filterContext)
        {
            string TempSession =
                Convert.ToString(filterContext.HttpContext.Session["AuthenticationToken"]);
            string TempAuthCookie = filterContext.HttpContext.Request.Cookies["AuthenticationToken"] != null ?
                Convert.ToString(filterContext.HttpContext.Request.Cookies["AuthenticationToken"].Value) : null;

            if (TempSession != null && TempAuthCookie != null)
            {
                if (!TempSession.Equals(TempAuthCookie))
                {
                    var url = new UrlHelper(filterContext.RequestContext);
                    var loginUrl = url.Action("Login", "Account", null);                    
                    filterContext.Result = new RedirectResult(loginUrl);
                }
            }
            else
            {
                var url = new UrlHelper(filterContext.RequestContext);
                var loginUrl = url.Action("Login", "Account", null);                
                filterContext.Result = new RedirectResult(loginUrl);
            }
        }
    }
}
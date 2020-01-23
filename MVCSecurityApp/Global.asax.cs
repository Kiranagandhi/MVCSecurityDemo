using MVCSecurityApp.Filters;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace MVCSecurityApp
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            MvcHandler.DisableMvcResponseHeader = true;
            GlobalFilters.Filters.Add(new UserAuditFilter()); // Register UserAuditFilter
        }

        protected void Application_PreSendRequestHeaders()
        {
            Response.Headers.Remove("Server");           //Remove Server Header    
            Response.Headers.Remove("X-AspNet-Version"); //Remove X-AspNet-Version Header
        }
    }
}

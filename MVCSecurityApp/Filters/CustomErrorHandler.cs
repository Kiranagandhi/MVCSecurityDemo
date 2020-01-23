using System;
using System.Web.Mvc;

namespace MVCSecurityApp.Filters
{
    public class CustomErrorHandler : HandleErrorAttribute
    {
        public override void OnException(ExceptionContext filterContext)
        {
            Exception e = filterContext.Exception;
            filterContext.ExceptionHandled = true;
            var result = new ViewResult()
            {
                ViewName = "Error"
            }; ;
            result.ViewBag.Error = "Error Occur While Processing Your Request Please Check After Some Time";
            filterContext.Result = result;
        }
    }
}
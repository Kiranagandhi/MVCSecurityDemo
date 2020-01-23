using MVCSecurityApp.Models;
using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using System.Linq;

namespace MVCSecurityApp.Controllers
{
    public class AccountController : Controller
    {
        AllSecurityDBEntities dbcon = new AllSecurityDBEntities();

        //
        // GET: /Account/Login


        [HttpGet]
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            LoginModel LM = new LoginModel();
            Random objRandom = new Random();

#pragma warning disable 618
            var Seed = FormsAuthentication.HashPasswordForStoringInConfigFile(Convert.ToString(objRandom.Next()), "MD5");
#pragma warning restore 618

            LM.hdrandomSeed = Seed;
            return View(LM);
        }

        //
        // POST: /Account/Login

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {   //Getting User details from Database
                var userDetails = GetUserDetails(model.UserName);
                // Comparing Password With Seed
                if (ReturnHash(userDetails.Password, model.hdrandomSeed) == model.Password)
                {
                    Session["Username"] = model.UserName;
                    Session["UserID"] = userDetails.UserId;

                    FormsAuthentication.SetAuthCookie(model.UserName, true);

                    // Getting New Guid
                    string guid = Convert.ToString(Guid.NewGuid());
                    //Storing new Guid in Session
                    Session["AuthenticationToken"] = guid;
                    //Adding Cookie in Browser
                    Response.Cookies.Add(new HttpCookie("AuthenticationToken", guid));


                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("", "The user name or password provided is incorrect.");
                }
            }
            return View(model);
        }

        //
        // ReturnHash
        [NonAction]
        public string ReturnHash(string strPassword, string token)
        {
            string strHash = null;
            string RandomNo = token;
#pragma warning disable 618
            return strHash = FormsAuthentication.HashPasswordForStoringInConfigFile((RandomNo + strPassword), "MD5");
#pragma warning restore 618
        }

        //
        // POST: /Account/LogOff
        public ActionResult LogOff()
        {
            //Removing Session
            Session.Abandon();
            Session.Clear();
            Session.RemoveAll();
            FormsAuthentication.SignOut();

            //Removing ASP.NET_SessionId Cookie
            if (Request.Cookies["ASP.NET_SessionId"] != null)
            {
                Response.Cookies["ASP.NET_SessionId"].Value = string.Empty;
                Response.Cookies["ASP.NET_SessionId"].Expires = DateTime.Now.AddMonths(-10);
            }

            if (Request.Cookies["AuthenticationToken"] != null)
            {
                Response.Cookies["AuthenticationToken"].Value = string.Empty;
                Response.Cookies["AuthenticationToken"].Expires = DateTime.Now.AddMonths(-10);
            }

            return RedirectToAction("Login", "Account");
        }

        public UserDetail GetUserDetails(string UserName)
        {
            UserDetail queryUserDetails = new UserDetail();

            using (AllSecurityDBEntities AS = new AllSecurityDBEntities())
            {
                queryUserDetails = (from user in AS.UserDetails
                                    where user.UserName == UserName
                                    select user).FirstOrDefault();
            }

            return queryUserDetails;
        }

        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                // Attempt to register the user
                try
                {
                    var checkUserExists = dbcon.UserDetails.Where(p => p.UserName.ToLower() == model.UserName.ToLower()).FirstOrDefault();

                    if (checkUserExists == null)
                    {
                        UserDetail userDetail = new UserDetail();
                        userDetail.UserName = model.UserName;
#pragma warning disable 618
                        var Password = FormsAuthentication.HashPasswordForStoringInConfigFile(model.Password, "MD5");
#pragma warning restore 618
                        userDetail.Password = Password;
                        userDetail.CreateDate = DateTime.Now;
                        dbcon.UserDetails.Add(userDetail);
                        dbcon.SaveChanges();

                        Session["Username"] = model.UserName;
                        Session["UserID"] = userDetail.UserId;

                        FormsAuthentication.SetAuthCookie(model.UserName, true);

                        // Getting New Guid
                        string guid = Convert.ToString(Guid.NewGuid());
                        //Storing new Guid in Session
                        Session["AuthenticationToken"] = guid;
                        //Adding Cookie in Browser
                        Response.Cookies.Add(new HttpCookie("AuthenticationToken", guid));

                        return RedirectToAction("Index", "Home");
                    }
                    else
                        ModelState.AddModelError("", ErrorCodeToString(MembershipCreateStatus.DuplicateUserName));
                }
                catch (MembershipCreateUserException e)
                {
                    ModelState.AddModelError("", ErrorCodeToString(e.StatusCode));
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
        }

        private static string ErrorCodeToString(MembershipCreateStatus createStatus)
        {
            // See http://go.microsoft.com/fwlink/?LinkID=177550 for
            // a full list of status codes.
            switch (createStatus)
            {
                case MembershipCreateStatus.DuplicateUserName:
                    return "User name already exists. Please enter a different user name.";

                case MembershipCreateStatus.DuplicateEmail:
                    return "A user name for that e-mail address already exists. Please enter a different e-mail address.";

                case MembershipCreateStatus.InvalidPassword:
                    return "The password provided is invalid. Please enter a valid password value.";

                case MembershipCreateStatus.InvalidEmail:
                    return "The e-mail address provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidAnswer:
                    return "The password retrieval answer provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidQuestion:
                    return "The password retrieval question provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidUserName:
                    return "The user name provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.ProviderError:
                    return "The authentication provider returned an error. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                case MembershipCreateStatus.UserRejected:
                    return "The user creation request has been canceled. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                default:
                    return "An unknown error occurred. Please verify your entry and try again. If the problem persists, please contact your system administrator.";
            }
        }
    }
}
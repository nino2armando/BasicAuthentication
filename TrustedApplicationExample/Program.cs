using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.SelfHost;
using Microsoft.IdentityModel.Tokens.JWT;
using TokenValidationParameters = Microsoft.IdentityModel.Tokens.JWT.TokenValidationParameters;
using System.Web.Http;
using System.Web.Http.SelfHost;   

namespace TrustedApplicationExample
{
    class Program
    {
        static void Main(string[] args)
        {
            var config = new HttpSelfHostConfiguration("https://localhost:8484");

            config.Routes.MapHttpRoute(
                "API Default", "api/{controller}/{id}",
                new { id = RouteParameter.Optional });

            using (HttpSelfHostServer server = new HttpSelfHostServer(config))
            {
                server.OpenAsync().Wait();
                Console.WriteLine("calling identity server");
                CallIdsrv();
                Console.WriteLine("Press Enter to quit.");
                Console.ReadLine();
                
            }



            // todo : look in here for the handler example 
            // todo: http://www.cloudidentity.com/blog/2013/01/09/using-the-jwt-handler-for-implementing-poor-man-s-delegation-actas/

            // IMPORTANT WE ARE NOT USING THE 
            //var certHanler = new WebRequestHandler();
            //certHanler.ClientCertificateOptions = ClientCertificateOption.Manual;

            //certHanler.UseDefaultCredentials = false;

            //X509Store store = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);
            //store.Open(OpenFlags.ReadOnly);

            //var certTest = store.Certificates;

            //X509Certificate2 certificate =
            //    store.Certificates.Find(X509FindType.FindByThumbprint, "471C43B8E34C8222CCF44A52AF5A9595624DA11E", false)[0];
            //store.Close();

            //certHanler.ClientCertificates.Add(certificate);   


        }

        public static void CallIdsrv()
        {
            var form = new FormUrlEncodedContent(
                new Dictionary<string, string>
                    {
                        {OAuth2Constants.GrantType, OAuth2Constants.Password},
                        {OAuth2Constants.UserName, "admin"},
                        {OAuth2Constants.Password, ""},
                        {OAuth2Constants.Scope, "https://localhost:8484"}
                    });

            var client = new HttpClient
                {
                    BaseAddress = new Uri("https://localhost/idsrv/issue/simple"),
                    DefaultRequestHeaders = {Authorization = new BasicAuthenticationHeaderValue("admin","")}
                };

            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
            client.DefaultRequestHeaders.Authorization = new BasicAuthenticationHeaderValue("test", ""); // {id},{secret}
            try
            {

              
                var task = client.PostAsync("https://localhost/idsrv/issue/simple", form);
                task.Wait();
                var response = task.Result;
                Console.WriteLine(response);
            }
            catch (Exception ex)
            {

                throw;
            }
        }
    }



    public class BasicAuthenticationHeaderValue : AuthenticationHeaderValue
    {
        public BasicAuthenticationHeaderValue(string userName, string password)
            : base("Basic", EncodeCredential(userName, password))
        { }

        private static string EncodeCredential(string userName, string password)
        {
            Encoding encoding = Encoding.GetEncoding("iso-8859-1");
            string credential = String.Format("{0}:{1}", userName, password);

            return Convert.ToBase64String(encoding.GetBytes(credential));
        }
    }

        public static class OAuth2Constants
    {
        public const string GrantType = "grant_type";
        public const string UserName  = "username";
        public const string Scope     = "scope";
        public const string Assertion = "assertion";
        public const string Password  = "password";
        public const string Code = "code";
        public const string RedirectUri = "redirect_uri";

        public static class GrantTypes
        {
            public const string Password          = "password";
            public const string AuthorizationCode = "authorization_code";
            public const string ClientCredentials = "client_credentials";
            public const string RefreshToken      = "refresh_token";
            public const string JWT               = "urn:ietf:params:oauth:grant-type:jwt-bearer";
            public const string Saml2             = "urn:ietf:params:oauth:grant-type:saml2-bearer";
        }

        public static class ResponseTypes
        {
            public const string Token = "token";
            public const string Code  = "code";
        }

        public static class Errors
        {
            public const string Error                   = "error";
            public const string InvalidRequest          = "invalid_request";
            public const string InvalidClient           = "invalid_client";
            public const string InvalidGrant            = "invalid_grant";
            public const string UnauthorizedClient      = "unauthorized_client";
            public const string UnsupportedGrantType    = "unsupported_grant_type";
            public const string UnsupportedResponseType = "unsupported_response_type";
            public const string InvalidScope            = "invalid_scope";
            public const string AccessDenied            = "access_denied";
        }
    }
}

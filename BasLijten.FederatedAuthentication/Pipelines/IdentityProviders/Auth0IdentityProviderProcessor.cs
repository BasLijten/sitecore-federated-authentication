// © 2017 Sitecore Corporation A/S. All rights reserved. Sitecore® is a registered trademark of Sitecore Corporation A/S.

using System.Threading.Tasks;
using Microsoft.Owin.Security;

using Owin;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System.Security.Claims;
using System.Web;

namespace BasLijten.FederatedAuthentication.Owin.Pipelines.IdentityProviders
{
    public class Auth0IdentityProviderProcessor : IdentityProvidersProcessor
    {
        public Auth0IdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
            
        }

        /// <summary>
        /// Identityprovidr name. Has to match the configuration
        /// </summary>
        protected override string IdentityProviderName
        {
            get { return "Auth0"; }
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider identityProvider = this.GetIdentityProvider();
            string authenticationType = this.GetAuthenticationType();

            var clientId = Sitecore.Configuration.Settings.GetSetting("FedAuth.Auth0.ClientId");
            var clientSecret = Sitecore.Configuration.Settings.GetSetting("FedAuth.Auth0.ClientSecret");
            var domain = Sitecore.Configuration.Settings.GetSetting("FedAuth.Auth0.Domain");

            var provider = new Auth0.Owin.Auth0AuthenticationProvider
            {
                OnAuthenticated = (context) =>
                {
                
                    // transform all claims
                    ClaimsIdentity identity = context.Identity;
                    foreach (Transformation current in identityProvider.Transformations)
                    {
                        current.Transform(identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));                        
                    }
                    return System.Threading.Tasks.Task.FromResult(0);
                },

                OnReturnEndpoint = (context) =>
                {
                    // xsrf validation
                    if (context.Request.Query["state"] != null && context.Request.Query["state"].Contains("xsrf="))
                    {
                        var state = HttpUtility.ParseQueryString(context.Request.Query["state"]);
                        //todo: do something with it.
                    }

                    return System.Threading.Tasks.Task.FromResult(0);
                }
            };

            // not needed yet.
            //Auth0AuthenticationOptions options = new Auth0AuthenticationOptions();


            // need to change these into settngs
            args.App.UseAuth0Authentication(
                clientId: clientId,
                clientSecret: clientSecret,
                domain: domain,
                provider: provider);


        }
    }

}

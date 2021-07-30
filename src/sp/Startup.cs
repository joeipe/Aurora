using System.Security.Cryptography.X509Certificates;
using Common;
using IdentityServer4.Saml;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Rsk.AspNetCore.Authentication.Saml2p;

namespace sp
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation();

            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = "cookie";
                    options.DefaultChallengeScheme = "saml";
                })
                .AddCookie("cookie")
                .AddSaml2p("saml", options =>
                {
                    // Describe ourselves (the SP)
                    options.ServiceProviderOptions = new SpOptions
                    {
                        EntityId = "https://localhost:5001",
                        SignAuthenticationRequests = false,
                        MetadataPath = "/saml/metadata"
                    };

                    // The IdP we want users to authenticate against - Local
                    options.IdentityProviderOptions = new IdpOptions
                    {
                        EntityId = "https://localhost:44321",
                        //SigningCertificates = {new X509Certificate2("idp_publickey.cer")},
                        SigningCertificates = { new X509Certificate2("joeidp_publickey.cer") },
                        SingleSignOnEndpoint = new SamlEndpoint("https://localhost:44321/saml/sso", SamlBindingTypes.HttpRedirect)
                    };

                    // The IdP we want users to authenticate against - Okta
                    /*options.IdentityProviderOptions = new IdpOptions
                    {
                        EntityId = "",
                        SigningCertificates = {new X509Certificate2(System.Convert.FromBase64String(""), "", X509KeyStorageFlags.EphemeralKeySet)},
                        SingleSignOnEndpoint = new SamlEndpoint("", SamlBindingTypes.HttpRedirect)
                    };*/

                    // our ACS URL
                    options.CallbackPath = "/saml/acs";

                    options.Licensee = DemoLicense.Licensee;
                    options.LicenseKey = DemoLicense.LicenseKey;

                    options.TimeComparisonTolerance = 300;
                });

            // in memory store for remembering SAML messages - for demos only
            services.AddScoped<ISamlMessageParser, SamlMessageParser>();
            services.AddSingleton<SamlMessageStore>();
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();
            
            app.UseHttpsRedirection();
            
            app.UseStaticFiles();
            app.UseRouting();

            app.Use(async (context, next) =>
            {
                if (context.Request.Path.Value?.Contains("/saml/acs") == true)
                {
                    var messageStore = context.RequestServices.GetRequiredService<SamlMessageStore>();
                    messageStore.CurrentMessage = context.Request.Form[SamlConstants.Parameters.SamlResponse];
                }

                await next();
            });
            
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
        }
    }

    public class SamlMessageStore
    {
        public string CurrentMessage { get; set; }
    }
}

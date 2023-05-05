using ARENAB.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.CodeAnalysis.Options;
//using Microsoft.AspNetCore.Identity.UI;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
//using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text.Json;
using System.Net.NetworkInformation;
using System.Text.Encodings.Web;
//using IdentityServer4;

namespace ARENAB
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));

            services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<ApplicationDbContext>();

            services.Configure<IdentityOptions>(options =>
            {
                // Password settings.
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = true;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 1;

                // Lockout settings.
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // User settings.
                options.User.AllowedUserNameCharacters =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                options.User.RequireUniqueEmail = false;
            });

            services.ConfigureApplicationCookie(options =>
            {
                // Cookie settings
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);

                options.LoginPath = "/Identity/Account/Login";
                options.AccessDeniedPath = "/Identity/Account/AccessDenied";
                options.SlidingExpiration = true;
            });
            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = "Google";
                }
                )

                //.AddGoogle(options =>
                //{
                //    options.ClientId = "901866681619-0tdogiltirvgn3niq4bmrulc0mjurh36.apps.googleusercontent.com";
                //    options.ClientSecret = "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";
                //    options.CallbackPath = "/signin-google";
                //}
                // )

            #region personalizado

                //.AddOAuth("Google", options =>
                // {
                //     options.ClientId = "901866681619 - 0tdogiltirvgn3niq4bmrulc0mjurh36.apps.googleusercontent.com";
                //     options.ClientSecret = "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";
                //     options.CallbackPath = "/signin-google";
                //     options.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/auth";
                //     options.TokenEndpoint = "https://oauth2.googleapis.com/token";
                //     // options.UserInformationEndpoint = "https://www.googleapis.com/oauth2/v3/userinfo";
                //     options.Scope.Add("email");
                //     options.SaveTokens = true;
                //     options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
                //     options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
                //     options.ClaimActions.MapJsonKey(ClaimTypes.GivenName, "given_name");
                //     options.ClaimActions.MapJsonKey(ClaimTypes.Surname, "family_name");
                //     options.ClaimActions.MapJsonKey("urn:google:profile", "link");
                //     options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
                //     options.ClaimActions.MapJsonKey("picture", "picture");

                //     options.Events = new OAuthEvents
                //     {

                //         OnCreatingTicket = async context =>
                //         {
                //             var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                //             request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                //             request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                //             var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
                //             response.EnsureSuccessStatusCode();

                //             var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

                //             context.RunClaimActions(user.RootElement);
                //         },
                //         OnRemoteFailure = context =>
                //         {
                //             context.Response.Redirect("/error?FailureMessage=" + UrlEncoder.Default.Encode(context.Failure.Message));
                //             context.HandleResponse();
                //             return Task.FromResult(0);
                //         }

                //     };
                // })



                //.AddOpenIdConnect(GoogleDefaults.AuthenticationScheme,options =>
                //{
                //    options.ClientId = "901866681619-0tdogiltirvgn3niq4bmrulc0mjurh36.apps.googleusercontent.com";
                //    options.ClientSecret = "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";
                //    options.Authority = "https://accounts.google.com/";
                //    options.CallbackPath = "/signin-google";
                //    options.SignedOutCallbackPath = "/signout-callback-google";
                //    options.SaveTokens = true;
                //    options.ResponseType = "code";
                //    options.Scope.Add("openid");
                //    options.Scope.Add("profile");
                //    options.Events.OnTicketReceived = context =>
                //    {
                //        // You can customize the claims here.
                //        return Task.CompletedTask;
                //    };
                //    options.Events.OnRemoteFailure = context =>
                //    {
                //        context.Response.Redirect("/error?FailureMessage=" + context.Failure.Message);
                //        context.HandleResponse();
                //        return Task.CompletedTask;
                //    };
                //})


                .AddOpenIdConnect("Google Scheme Ejemplo", "Google Login", options =>
                {
                    options.ClientId = "901866681619-0tdogiltirvgn3niq4bmrulc0mjurh36.apps.googleusercontent.com";
                    options.ClientSecret = "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";
                    options.Authority = "https://accounts.google.com/";
                    options.CallbackPath = "/signin-google";
                    options.SignedOutCallbackPath = "/signout-callback-google";
                    options.SaveTokens = true;
                    options.ResponseType = "code";
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    options.Events.OnTicketReceived = context =>
                    {
                        // You can customize the claims here.
                        return Task.CompletedTask;
                    };
                    options.Events.OnRemoteFailure = context =>
                    {
                        context.Response.Redirect("/error?FailureMessage=" + context.Failure.Message);
                        context.HandleResponse();
                        return Task.CompletedTask;
                    };
                })

                 .AddOpenIdConnect("Panama Digital Autenticacion", "Panama Digital Login", options =>
                 {
                     options.ClientId = "901866681619-0tdogiltirvgn3niq4bmrulc0mjurh36.apps.googleusercontent.com";
                     options.ClientSecret = "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";
                     options.Authority = "https://accounts.google.com/";
                     options.CallbackPath = "/signin-google";
                     options.SignedOutCallbackPath = "/signout-callback-google";
                     options.SaveTokens = true;
                     options.ResponseType = "code";
                     options.Scope.Add("openid");
                     options.Scope.Add("profile");
                     options.Events.OnTicketReceived = context =>
                     {
                         // You can customize the claims here.
                         return Task.CompletedTask;
                     };
                     options.Events.OnRemoteFailure = context =>
                     {
                         context.Response.Redirect("/error?FailureMessage=" + context.Failure.Message);
                         context.HandleResponse();
                         return Task.CompletedTask;
                     };
                 })





            #endregion personalizado

                  ;//termina los providers de autenticacion





            //services.AddCors(options =>
            //{
            //    options.AddPolicy("CorsPolicy", builder =>
            //    {
            //        builder.WithOrigins("http://localhost:3000") // Agrega los orígenes permitidos
            //               .AllowAnyHeader()
            //               .AllowAnyMethod();
            //    });
            //});




        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }

       

        
    }
}

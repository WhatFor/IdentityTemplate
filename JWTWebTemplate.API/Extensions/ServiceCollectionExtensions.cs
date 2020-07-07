using System;
using System.Security.Claims;
using System.Text;
using JWTWebTemplate.Models;
using JWTWebTemplate.Models.Domain.Account;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace JWTWebTemplate.API.Extensions
{
    /// <summary>
    /// Extension methods for configuring Identity in different ways.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Configure Identity with sensible defaults for a session authenticated application.
        /// Works well for MVC or Razor Pages.
        /// </summary>
        /// <example>
        /// For reading on how to scaffold Identity pages, see:
        ///     https://docs.microsoft.com/en-us/aspnet/core/security/authentication/scaffold-identity
        ///     Note: Be sure to check the relevant section for your needs.
        ///
        /// For documentation on Identity configuration, see:
        ///     https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-3.1
        /// </example>
        public static IServiceCollection ConfigureIdentityForSession(this IServiceCollection services, IConfiguration config)
        {
            // Tell Identity which User and Role models we want to use,
            services.AddIdentity<ApplicationUser, ApplicationRole>()
                
                // Tell Identity we're using EF to store users + roles,
                .AddEntityFrameworkStores<ApplicationDbContext>()
                
                // And add in default token providers.
                .AddDefaultTokenProviders();
            
            // Set up sensible defaults for Identity.
            services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireUppercase = true;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 1;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                options.User.RequireUniqueEmail = true;
            });
            
            // Add cookie
            services
                .AddAuthentication()
                .AddCookie(o =>
                {
                    o.AccessDeniedPath = "/Error";
                    o.LogoutPath = "/Account/Login?handler=Logout";
                    o.LoginPath = "/Account/Login";
                });
            
            // Configure Cookie
            services.ConfigureApplicationCookie(options =>
            {
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                options.SlidingExpiration = true;
            });
            
            return services;
        }
        
        /// <summary>
        /// Configure Identity with sensible defaults for a JWT authenticated application.
        /// Works well for SPAs.
        /// </summary>
        public static IServiceCollection ConfigureIdentityForJwt(this IServiceCollection services, IConfiguration config)
        {
            services.AddIdentity<ApplicationUser, ApplicationRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
            
            services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 1;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                options.User.RequireUniqueEmail = true;
            });
            
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.GetSection("Jwt").GetValue<string>("Key")));
            
            services
                .AddAuthentication()
                .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, o =>
                {
                    o.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidIssuer = config.GetSection("Jwt").GetValue<string>("Issuer"),
                        ValidateAudience = true,
                        ValidAudience = config.GetSection("Jwt").GetValue<string>("Audience"),
                        NameClaimType = ClaimTypes.NameIdentifier,
                        IssuerSigningKey = key,
                    };
                });
            
            return services;
        }
    }
}
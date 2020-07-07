using JWTWebTemplate.API.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace JWTWebTemplate.API
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        protected AuthenticationMode Mode = AuthenticationMode.JWT;

        public void ConfigureServices(IServiceCollection services)
        {
            if (Mode == AuthenticationMode.JWT)
            {
                services.ConfigureIdentityForJwt(Configuration);
            }
            else
            {
                services.ConfigureIdentityForSession(Configuration);
            }
            
            services.AddControllers();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHttpsRedirection();
            }

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
            app.UseCookiePolicy();
        }
    }

    public enum AuthenticationMode
    {
        JWT,
        Session
    }
}
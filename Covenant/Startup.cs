// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Threading;
using System.Reflection;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.HttpOverrides;
using Swashbuckle.AspNetCore.Swagger;
using Swashbuckle.AspNetCore.SwaggerGen;

using Covenant.Hubs;
using Covenant.API;
using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;
using System.Net;

namespace Covenant
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
            services.AddDbContext<CovenantContext>();

            services.AddIdentity<CovenantUser, IdentityRole>()
                .AddEntityFrameworkStores<CovenantContext>()
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredLength = 1;

                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
                options.Lockout.MaxFailedAccessAttempts = 10;
                options.Lockout.AllowedForNewUsers = true;

                options.User.RequireUniqueEmail = false;
            });
            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.KnownProxies.Add(IPAddress.Parse(Configuration["TrustedProxies"]));
            });

            services.ConfigureApplicationCookie(options =>
            {
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(120);

                options.LoginPath = "/CovenantUser/Login";
                options.LogoutPath = "/CovenantUser/Logout";
                options.AccessDeniedPath = "/Login/AccessDenied";
                options.SlidingExpiration = true;
            });

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            services.AddAuthentication()
                .AddJwtBearer("JwtBearer", options =>
                {
                    options.RequireHttpsMetadata = false;
                    options.SaveToken = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidIssuer = Configuration["JwtIssuer"],
                        ValidAudience = Configuration["JwtAudience"],
                        IssuerSigningKey = new SymmetricSecurityKey(Common.CovenantEncoding.GetBytes(Configuration["JwtKey"])),
                        ClockSkew = TimeSpan.Zero
                    };
                    options.Events = new JwtBearerEvents
                    {
                        OnMessageReceived = context =>
                        {
                            var accessToken = context.Request.Query["access_token"];
                            var path = context.HttpContext.Request.Path;
                            if (!string.IsNullOrEmpty(accessToken) && (context.HttpContext.WebSockets.IsWebSocketRequest || context.Request.Headers["accept"] == "text/event-stream"))
                            {
                                context.Token = context.Request.Query["access_token"];
                            }
                            return System.Threading.Tasks.Task.CompletedTask;
                        }
                    };
                });

            services.AddAuthorization(options =>
            {
                options.DefaultPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes("JwtBearer", "Identity.Application")
                    .Build();
                options.AddPolicy("RequireAdministratorRole", new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes("JwtBearer", "Identity.Application")
                    .RequireRole("Administrator")
                    .Build());
                options.AddPolicy("RequireJwtBearer", new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes("JwtBearer")
                    .Build());
                options.AddPolicy("RequireJwtBearerRequireAdministratorRole", new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddAuthenticationSchemes("JwtBearer")
                    .RequireRole("Administrator")
                    .Build());
            });

            services.AddMvc().AddJsonOptions(options =>
            {
                options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
            }).SetCompatibilityVersion(Microsoft.AspNetCore.Mvc.CompatibilityVersion.Version_2_2);
            services.AddRouting(options => options.LowercaseUrls = true);
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new Info { Title = "Covenant API", Version = "v0.1" });
                c.AddSecurityDefinition("Bearer", new ApiKeyScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                    Name = "Authorization",
                    In = "header",
                    Type = "apiKey"
                });
                c.SchemaFilter<EnumSchemaFilter>();
                c.SchemaFilter<AutoRestSchemaFilter>();
            });

            services.AddSignalR().AddJsonProtocol(options =>
            {
                options.PayloadSerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
            });

            services.AddSingleton<ConcurrentDictionary<int, CancellationTokenSource>>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c =>
                {
                    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Covenant API V0.1");
                });
                app.Use((context, next) =>
                {
                    context.Response.Headers.Remove("Server");
                    return next();
                });
            }
            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
            });

			app.UseAuthentication();

            app.UseStaticFiles();
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "defaultWithoutAction",
                    template: "{controller=Home}/{id?}"
                );
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}"
                );
            });

            app.UseSignalR(routes =>
            {
                routes.MapHub<GruntHub>("/grunthub", options =>
                {
                    options.ApplicationMaxBufferSize = 2000 * 1024;
                });
                routes.MapHub<EventHub>("/eventhub");
            });
        }

        public class AutoRestSchemaFilter : ISchemaFilter
        {
            public void Apply(Schema schema, SchemaFilterContext context)
            {
                var typeInfo = context.SystemType.GetTypeInfo();

                if (typeInfo.IsEnum)
                {
                    schema.Extensions.Add(
                        "x-ms-enum",
                        new { name = typeInfo.Name, modelAsString = false }
                    );
                }
            }
        }

        public class EnumSchemaFilter : ISchemaFilter
        {
            public void Apply(Schema model, SchemaFilterContext context)
            {
                if (model.Properties == null)
                    return;

                var enumProperties = model.Properties.Where(p => p.Value.Enum != null)
                    .Union(model.Properties.Where(p => p.Value.Items?.Enum != null)).ToList();
                var enums = context.SystemType.GetProperties()
                    .Select(p => Nullable.GetUnderlyingType(p.PropertyType) ?? p.PropertyType.GetElementType() ??
                                    p.PropertyType.GetGenericArguments().FirstOrDefault() ?? p.PropertyType)
                    .Where(p => p.GetTypeInfo().IsEnum)
                    .ToList();

                foreach (var enumProperty in enumProperties)
                {
                    var enumPropertyValue = enumProperty.Value.Enum != null ? enumProperty.Value : enumProperty.Value.Items;
                    enumPropertyValue.Type = "string";
                    enumPropertyValue.Format = null;
                    var enumValues = enumPropertyValue.Enum.Select(e => $"{e}").ToList();
                    enumPropertyValue.Enum = new List<Object>(enumValues);
                    var enumType = enums.SingleOrDefault(p =>
                    {
                        var enumNames = Enum.GetNames(p);
                        if (enumNames.Except(enumValues, StringComparer.InvariantCultureIgnoreCase).Any())
                            return false;
                        if (enumValues.Except(enumNames, StringComparer.InvariantCultureIgnoreCase).Any())
                            return false;
                        return true;
                    });

                    if (enumType == null)
                        throw new Exception($"Property {enumProperty} not found in {context.SystemType.Name} Type.");

                    if (context.SchemaRegistry.Definitions.ContainsKey(enumType.Name) == false)
                        context.SchemaRegistry.Definitions.Add(enumType.Name, enumPropertyValue);

                    var schema = new Schema
                    {
                        Ref = $"#/definitions/{enumType.Name}"
                    };
                    if (enumProperty.Value.Enum != null)
                    {
                        model.Properties[enumProperty.Key] = schema;
                    }
                    else if (enumProperty.Value.Items?.Enum != null)
                    {
                        enumProperty.Value.Items = schema;
                    }
                }
            }

        }
    }
}

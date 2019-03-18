// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Collections.Generic;
using System.Threading;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

using Swashbuckle.AspNetCore.Swagger;
using Swashbuckle.AspNetCore.SwaggerGen;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;

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
            services.AddDbContext<CovenantContext>(opt =>
			{
				opt.UseSqlite("Data Source=" + Common.CovenantDatabaseFile);
			});
            
            services.AddIdentity<CovenantUser, IdentityRole>(options =>
            {
                options.Stores.MaxLengthForKeys = 128;
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredLength = 1;
            }).AddEntityFrameworkStores<CovenantContext>()
            .AddDefaultTokenProviders();

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
			services.AddAuthentication(options =>
			{
				options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
				options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
			}).AddJwtBearer(cfg =>
			{
				cfg.RequireHttpsMetadata = false;
				cfg.SaveToken = true;
				cfg.TokenValidationParameters = new TokenValidationParameters
				{
					ValidIssuer = Configuration["JwtIssuer"],
					ValidAudience = Configuration["JwtAudience"],
					IssuerSigningKey = new SymmetricSecurityKey(Common.CovenantEncoding.GetBytes(Configuration["JwtKey"])),
					ClockSkew = TimeSpan.Zero
				};
			});

            services.AddMvc();
            services.AddRouting(options => options.LowercaseUrls = true);

			services.AddAuthorization(options =>
			{
				options.AddPolicy("RequireAdministratorRole", policy => policy.RequireRole("Administrator"));
            });

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

			services.AddSingleton<Dictionary<int, CancellationTokenSource>>();
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

			app.UseAuthentication();
            app.UseMvc();
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
                };
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
// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using NLog.Web;
using NLog.Config;
using NLog.Targets;

using Newtonsoft.Json;

using Covenant.Core;
using APIModels = Covenant.API.Models;

namespace Covenant.Models.Listeners
{
    public class HostedFile
    {
        public int Id { get; set; }
        public int ListenerId { get; set; }
        public string Path { get; set; }
        public string Content { get; set; }
    }

    public class HttpListener : Listener
    {
        [Required]
        [DisplayName("UseSSL")]
        public bool UseSSL { get; set; } = false;
        private string SSLCertificateFile { get { return this.ListenerDirectory + "httplistener-" + this.GUID + "-certificate.pfx"; } }
        [DisplayName("SSLCertificate")]
        public string SSLCertificate { get; set; }
        [DisplayName("SSLCertificatePassword")]
        public string SSLCertificatePassword { get; set; } = "CovenantDev";

        [DisplayName("SSLCertHash")]
        public string SSLCertHash
        {
            get
            {
                if (!UseSSL || !File.Exists(SSLCertificateFile)) { return ""; }
                try
                {
                    X509Certificate2 cert = new X509Certificate2(SSLCertificateFile, this.SSLCertificatePassword);
                    return cert.GetCertHashString();
                }
                catch (Exception) { return ""; }
            }
            set { _ = value; }
        }

        [Required]
        public List<string> Urls
        {
            get
            {
                List<string> urls = new List<string>();
                foreach (string ConnectAddress in this.ConnectAddresses)
                {
                    string scheme = UseSSL ? "https://" : "http://";
                    urls.Add(scheme + ConnectAddress + ":" + this.ConnectPort);
                }
                return urls;
            }
            set
            {
                List<string> addresses = new List<string>();
                foreach (string url in value)
                {
                    Uri uri = new Uri(url);
                    this.UseSSL = uri.Scheme == "https";
                    addresses.Add(uri.Host);
                    this.ConnectPort = uri.Port;
                }
                this.ConnectAddresses = addresses;
            }
        }

        private string ListenerStaticHostDirectory { get { return this.ListenerDirectory + "Static" + Path.DirectorySeparatorChar; } }

        public HttpListener()
        {
            this.Description = "Listens on HTTP protocol.";
        }

        public HttpListener(int ListenerTypeId, int ProfileId) : this()
        {
            this.ListenerTypeId = ListenerTypeId;
            this.ProfileId = ProfileId;
            try
            {
                this.ConnectAddresses = new List<string> {
                    Dns.GetHostAddresses(Dns.GetHostName())
                        .FirstOrDefault(A => A.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        .ToString()
                };
            }
            catch (Exception)
            {
                this.ConnectAddresses = new List<string> { "" };
            }
        }

        public HttpListener(ListenerType type, Profile profile) : this(type.Id, profile.Id)
        {
            this.ListenerType = type;
            this.Profile = profile;
        }

        private bool CreateDirectories()
        {
            if (!Directory.Exists(this.ListenerDirectory))
            {
                Directory.CreateDirectory(this.ListenerDirectory);
            }
            if (!Directory.Exists(this.ListenerStaticHostDirectory))
            {
                Directory.CreateDirectory(this.ListenerStaticHostDirectory);
            }
            return Directory.Exists(this.ListenerDirectory) && Directory.Exists(this.ListenerStaticHostDirectory);
        }

        public override CancellationTokenSource Start()
        {
            IHost host = BuildHost();

            using (var scope = host.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                HttpListenerContext context = services.GetRequiredService<HttpListenerContext>();
                context.Database.EnsureCreated();
                foreach (APIModels.HttpProfile profile in context.HttpProfiles)
                {
                    context.HttpProfiles.Remove(profile);
                }
                context.HttpProfiles.Add(context.ToHttpProfile((HttpProfile)this.Profile));
                context.SaveChanges();
                InternalListener internalListener = services.GetRequiredService<InternalListener>();
                IConfiguration configuration = services.GetRequiredService<IConfiguration>();
                _ = internalListener.Configure(InternalListener.ToProfile(this.Profile), this.GUID, configuration["CovenantUrl"], configuration["CovenantToken"]);
            }
            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
            LoggingConfiguration loggingConfig = new LoggingConfiguration();
            using (var consoleTarget = new ColoredConsoleTarget())
            {
                using (var fileTarget = new FileTarget())
                {
                    loggingConfig.AddTarget("console", consoleTarget);
                    loggingConfig.AddTarget("file", fileTarget);
                    consoleTarget.Layout = @"${longdate}|${event-properties:item=EventId_Id}|${uppercase:${level}}|${logger}|${message} ${exception:format=tostring}";
                    fileTarget.Layout = @"${longdate}|${event-properties:item=EventId_Id}|${uppercase:${level}}|${logger}|${message} ${exception:format=tostring}";
                    fileTarget.FileName = Common.CovenantLogDirectory + "covenant-http.log";
                    loggingConfig.AddRule(NLog.LogLevel.Warn, NLog.LogLevel.Fatal, "console");
                    loggingConfig.AddRule(NLog.LogLevel.Warn, NLog.LogLevel.Fatal, "file");

                    var logger = NLogBuilder.ConfigureNLog(loggingConfig).GetCurrentClassLogger();

                    System.Threading.Tasks.Task task = host.RunAsync(cancellationTokenSource.Token);
                    // Don't love this, but we wait to see if the Listener throws an error on Startup
                    Thread.Sleep(500);
                    if (task.Status == System.Threading.Tasks.TaskStatus.Faulted)
                    {
                        throw new ListenerStartException(task.Exception.Message);
                    }
                    this.Status = ListenerStatus.Active;
                    return cancellationTokenSource;
                }
            }
        }

        public override void Stop(CancellationTokenSource cancellationTokenSource)
        {
            if (this.Status == ListenerStatus.Active)
            {
                cancellationTokenSource.Cancel();
                this.Status = ListenerStatus.Stopped;
            }
        }

        private IHost BuildHost()
        {
            this.CreateDirectories();
            return new HostBuilder()
                .ConfigureWebHost(webconfig =>
                {
                    webconfig.UseKestrel(options =>
                    {
                        options.AddServerHeader = false;
                        if (UseSSL)
                        {
                            File.WriteAllBytes(this.SSLCertificateFile, Convert.FromBase64String(this.SSLCertificate));
                            options.Listen(new IPEndPoint(IPAddress.Parse(this.BindAddress), this.BindPort), listenOptions =>
                            {
                                listenOptions.UseHttps(httpsOptions =>
                                {
                                    httpsOptions.ServerCertificate = new X509Certificate2(SSLCertificateFile, this.SSLCertificatePassword);
                                    httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                                                                System.Security.Authentication.SslProtocols.Tls11 |
                                                                System.Security.Authentication.SslProtocols.Tls;
                                });
                            });
                        }
                    })
                    .UseContentRoot(Directory.GetCurrentDirectory())
                    .ConfigureLogging((hostingContext, logging) =>
                    {
                        // logging.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
                        logging.AddConsole();
                        logging.AddDebug();
                        logging.AddFilter("System", LogLevel.Warning)
                            .AddFilter("Microsoft", LogLevel.Warning);
                    })
                    .UseNLog()
                    .UseStartup<HttpListenerStartup>()
                    .UseSetting("CovenantUrl", this.CovenantUrl)
                    .UseSetting("CovenantToken", this.CovenantToken)
                    .UseSetting("ProfileUrls", JsonConvert.SerializeObject((this.Profile as HttpProfile).HttpUrls))
                    .UseSetting("ListenerStaticHostDirectory", this.ListenerStaticHostDirectory)
                    .UseUrls((this.UseSSL ? "https://" : "http://") + this.BindAddress + ":" + this.BindPort);
                })
                .Build();
        }

        public HostedFile HostFile(HostedFile hostFileRequest)
        {
            hostFileRequest.Path = hostFileRequest.Path.TrimStart('/').TrimStart('\\');
            string FullPath = Path.GetFullPath(Path.Combine(this.ListenerStaticHostDirectory, hostFileRequest.Path));
            if (!FullPath.StartsWith(this.ListenerStaticHostDirectory, StringComparison.OrdinalIgnoreCase)) { throw new CovenantDirectoryTraversalException(); }
            FileInfo file1 = new FileInfo(FullPath);
            string filename = Utilities.GetSanitizedFilename(file1.Name);
            FileInfo file = new FileInfo(file1.DirectoryName + Path.DirectorySeparatorChar + filename);
            if (!file.Directory.Exists)
            {
                file.Directory.Create();
            }
            string uriPath = file.FullName.Replace(this.ListenerStaticHostDirectory, "");
            Uri uri = new Uri(this.Urls.FirstOrDefault() + "/" + uriPath);
            hostFileRequest.Path = uri.AbsolutePath;
            File.WriteAllBytes(file.FullName, Convert.FromBase64String(hostFileRequest.Content));
            return hostFileRequest;
        }

        public void UnhostFile(HostedFile hostFileRequest)
        {
            string FullPath = Path.GetFullPath(Path.Combine(this.ListenerStaticHostDirectory, hostFileRequest.Path));
            if (!FullPath.StartsWith(this.ListenerStaticHostDirectory, StringComparison.OrdinalIgnoreCase)) { throw new CovenantDirectoryTraversalException(); }
            FileInfo file = new FileInfo(FullPath);
            if (file.Exists)
            {
                file.Delete();
            }
        }
    }

    public class HttpListenerContext : IdentityDbContext
    {
        public DbSet<APIModels.HttpProfile> HttpProfiles { get; set; }

        public HttpListenerContext(DbContextOptions<HttpListenerContext> options) : base(options)
        {

        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
            => optionsBuilder.UseInMemoryDatabase("HttpListenerDatabase");

        protected override void OnModelCreating(ModelBuilder builder)
        {
            ValueComparer<IList<string>> stringIListComparer = new ValueComparer<IList<string>>(
                (c1, c2) => c1.SequenceEqual(c1),
                c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
                c => c
            );
            ValueComparer<IList<APIModels.HttpProfileHeader>> httpProfileHeaderIListComparer = new ValueComparer<IList<APIModels.HttpProfileHeader>>(
                (c1, c2) => c1.SequenceEqual(c1),
                c => c.Aggregate(0, (a, v) => HashCode.Combine(a, v.GetHashCode())),
                c => c
            );

            builder.Entity<APIModels.HttpProfile>().Property(HP => HP.HttpUrls).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<string>() : JsonConvert.DeserializeObject<List<string>>(v)
            ).Metadata.SetValueComparer(stringIListComparer);
            builder.Entity<APIModels.HttpProfile>().Property(HP => HP.HttpRequestHeaders).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<APIModels.HttpProfileHeader>() : JsonConvert.DeserializeObject<List<APIModels.HttpProfileHeader>>(v)
            ).Metadata.SetValueComparer(httpProfileHeaderIListComparer);
            builder.Entity<APIModels.HttpProfile>().Property(HP => HP.HttpResponseHeaders).HasConversion
            (
                v => JsonConvert.SerializeObject(v),
                v => v == null ? new List<APIModels.HttpProfileHeader>() : JsonConvert.DeserializeObject<List<APIModels.HttpProfileHeader>>(v)
            ).Metadata.SetValueComparer(httpProfileHeaderIListComparer);
            base.OnModelCreating(builder);
        }

        public APIModels.HttpProfile ToHttpProfile(HttpProfile profile)
        {
            return new APIModels.HttpProfile
            {
                Id = profile.Id,
                Name = profile.Name,
                Type = (APIModels.ProfileType)Enum.Parse(typeof(APIModels.ProfileType), profile.Type.ToString(), true),
                Description = profile.Description,
                MessageTransform = profile.MessageTransform,
                HttpGetResponse = profile.HttpGetResponse,
                HttpPostRequest = profile.HttpPostRequest,
                HttpPostResponse = profile.HttpPostResponse,
                HttpRequestHeaders = profile.HttpRequestHeaders.Select(HRH => new APIModels.HttpProfileHeader { Name = HRH.Name, Value = HRH.Value }).ToList(),
                HttpResponseHeaders = profile.HttpResponseHeaders.Select(HRH => new APIModels.HttpProfileHeader { Name = HRH.Name, Value = HRH.Value }).ToList(),
                HttpUrls = profile.HttpUrls
            };
        }
    }

    public class HttpListenerStartup
    {
        public IConfiguration Configuration { get; }
        public HttpListenerStartup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<HttpListenerContext>();
            services.AddSingleton<InternalListener>(IL => new InternalListener());
            services.AddMvc();
            services.AddAuthorization(options =>
            {
                options.AddPolicy("RequireAdministratorRole", policy => policy.RequireRole("Administrator"));
                options.AddPolicy("RequireJwtBearer", policy =>
                {
                    policy.AuthenticationSchemes.Add(JwtBearerDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                });
                options.AddPolicy("RequireJwtBearerRequireAdministratorRole", policy =>
                {
                    policy.AuthenticationSchemes.Add(JwtBearerDefaults.AuthenticationScheme);
                    policy.RequireRole("Administrator");
                });
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app)
        {
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                foreach (string route in JsonConvert.DeserializeObject<List<string>>(Configuration["ProfileUrls"]))
                {
                    string urlOnly = route.Split("?").First();
                    endpoints.MapControllerRoute(urlOnly, urlOnly, new { controller = "HttpListener", action = "Route" });
                }
            });

            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(Configuration["ListenerStaticHostDirectory"]),
                RequestPath = "",
                ContentTypeProvider = new FileExtensionContentTypeProvider(Common.ContentTypeMappings),
                ServeUnknownFileTypes = true,
                DefaultContentType = "text/plain"
            });
        }
    }
}

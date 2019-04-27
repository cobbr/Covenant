// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using NLog.Web;
using NLog.Config;
using NLog.Targets;

using Newtonsoft.Json;

using Covenant.API;
using APIModels = Covenant.API.Models;
using Covenant.Models.Grunts;
using Covenant.Core;

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
        public bool UseSSL { get; set; } = false;
        private string _SSLCertificateFile
        {
            get
            {
                return Common.CovenantResourceDirectory + "httplistener-" + this.Id + "-certificate.pfx";
            }
        }
        private string _SSLCertificate = "";
        public string SSLCertificate
        {
            get
            {
                return _SSLCertificate;
            }
            set
            {
                _SSLCertificate = value;
                if (_SSLCertificate != "")
                {
                    File.WriteAllBytes(_SSLCertificateFile, Convert.FromBase64String(value));
                }
            }
        }

        public string SSLCertificatePassword { get; set; } = "CovenantDev";

        public string SSLCertHash
        {
            get
            {
                if (_SSLCertificate == "" || !File.Exists(_SSLCertificateFile)) { return ""; }
                try
                {
                    X509Certificate2 cert = new X509Certificate2(_SSLCertificateFile, this.SSLCertificatePassword);
                    return cert.GetCertHashString();
                }
                catch (Exception) { return ""; }
            }
        }

        public string Url
        {
            get
            {
                string scheme = (UseSSL ? "https://" : "http://");
                return scheme + this.ConnectAddress + ":" + this.BindPort; 
            }
            set
            {
                Uri uri = new Uri(value);
                this.UseSSL = uri.Scheme == "https";
                this.ConnectAddress = uri.Host;
                this.BindPort = uri.Port;
            }
        }

        public HttpListener()
        {
            this.Description = "Listens on HTTP protocol.";
        }

        public HttpListener(int ListenerTypeId, int ProfileId) : this()
        {
            this.ListenerTypeId = ListenerTypeId;
            this.ProfileId = ProfileId;
        }

        public static HttpListener Create(APIModels.HttpListener httpListenerModel)
        {
            HttpListener listener = new HttpListener(httpListenerModel.ListenerTypeId ?? default, httpListenerModel.ProfileId ?? default);
            listener.Id = httpListenerModel.Id ?? default;
            listener.Name = httpListenerModel.Name;
            listener.Description = httpListenerModel.Description;
            listener.ProfileId = httpListenerModel.ProfileId ?? default;
            listener.UseSSL = httpListenerModel.UseSSL ?? default;
            listener.SSLCertificate = httpListenerModel.SslCertificate;
            listener.SSLCertificatePassword = httpListenerModel.SslCertificatePassword;
            listener.Url = httpListenerModel.Url;
            listener.ConnectAddress = httpListenerModel.ConnectAddress;
            listener.BindAddress = httpListenerModel.BindAddress;
            listener.BindPort = httpListenerModel.BindPort ?? default;
            listener.ListenerTypeId = httpListenerModel.ListenerTypeId ?? default;
            listener.Status = (ListenerStatus)Enum.Parse(typeof(ListenerStatus), httpListenerModel.Status.ToString());
            listener.CovenantToken = httpListenerModel.CovenantToken;
            return listener;
        }
        
        public override CancellationTokenSource Start(HttpProfile profile)
        {
            IWebHost host = BuildWebHost(profile);

            using (var scope = host.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                HttpListenerContext context = services.GetRequiredService<HttpListenerContext>();
                context.Database.EnsureCreated();
                if (!context.Listener.Any())
                {
                    context.Listener.Add(this);
                }
                context.SaveChanges();
            }
            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
            LoggingConfiguration loggingConfig = new LoggingConfiguration();
            var consoleTarget = new ColoredConsoleTarget();
            var fileTarget = new FileTarget();
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
            Thread.Sleep(100);
            if (task.Status != System.Threading.Tasks.TaskStatus.Faulted)
            {
                this.Status = ListenerStatus.Active;
                return cancellationTokenSource;
            }
            return null;
        }

        public override void Stop(CancellationTokenSource cancellationTokenSource)
        {
            if (this.Status == ListenerStatus.Active)
            {
                cancellationTokenSource.Cancel();
                this.Status = ListenerStatus.Stopped;
            }
        }

        private IWebHost BuildWebHost(HttpProfile profile)
        {
            WebHostBuilder builder = new WebHostBuilder();
            builder.UseKestrel(options =>
            {
                options.AddServerHeader = false;
                if (UseSSL)
                {
                    options.Listen(new IPEndPoint(IPAddress.Parse(this.BindAddress), this.BindPort), listenOptions =>
                    {
                        listenOptions.UseHttps(httpsOptions =>
                        {
                            httpsOptions.ServerCertificate = new X509Certificate2(_SSLCertificateFile, this.SSLCertificatePassword);
                            httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                                                        System.Security.Authentication.SslProtocols.Tls11 |
                                                        System.Security.Authentication.SslProtocols.Tls;
                        });
                    });
                }
            });
            
            return builder.UseContentRoot(Directory.GetCurrentDirectory())
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
                    .UseSetting("CovenantToken", this.CovenantToken)
                    .UseSetting("ProfileUrls", profile.HttpUrls)
                    .UseUrls((this.UseSSL ? "https://" : "http://") + this.BindAddress + ":" + this.BindPort)
                    .Build();
        }

        public HostedFile HostFile(HostedFile hostFileRequest)
        {
            hostFileRequest.Path = hostFileRequest.Path.TrimStart('/').TrimStart('\\');
            string FullPath = Path.GetFullPath(Path.Combine(Common.CovenantStaticHostDirectory, hostFileRequest.Path));
            if (!FullPath.StartsWith(Common.CovenantStaticHostDirectory, StringComparison.OrdinalIgnoreCase)) { throw new CovenantDirectoryTraversalException(); }
            FileInfo file = new FileInfo(FullPath);
            if (!file.Directory.Exists)
            {
                file.Directory.Create();
            }
            foreach (char invalid in Path.GetInvalidFileNameChars())
            {
                file.Name.Replace(invalid, '_');
            }
            string uriPath = file.FullName.Replace(Common.CovenantStaticHostDirectory, "");
            Uri uri = new Uri(this.Url + "/" + uriPath);
            hostFileRequest.Path = uri.AbsolutePath;
            File.WriteAllBytes(file.FullName, Convert.FromBase64String(hostFileRequest.Content));
            return hostFileRequest;
        }

        public void UnhostFile(HostedFile hostFileRequest)
        {
            string FullPath = Path.GetFullPath(Path.Combine(Common.CovenantStaticHostDirectory, hostFileRequest.Path));
            if (!FullPath.StartsWith(Common.CovenantStaticHostDirectory, StringComparison.OrdinalIgnoreCase)) { throw new CovenantDirectoryTraversalException(); }
            FileInfo file = new FileInfo(FullPath);
            if(file.Exists)
            {
                file.Delete();
            }
        }

        public override string GetGruntStagerCode(Grunt grunt, HttpProfile profile)
        {
            return this.GruntTemplateReplace(GruntStagerTemplateCode, grunt, profile);
        }

        public override string GetGruntExecutorCode(Grunt grunt, HttpProfile profile)
        {
            return this.GruntTemplateReplace(GruntExecutorTemplateCode, grunt, profile);
        }

        private string GruntTemplateReplace(string CodeTemplate, Grunt grunt, HttpProfile profile)
        {
            string ConnectUrl = (this.UseSSL ? "https://" : "http://") + this.ConnectAddress + ":" + this.BindPort;
            string HttpHeaders = "";
            foreach (HttpProfile.HttpProfileHeader header in JsonConvert.DeserializeObject<List<HttpProfile.HttpProfileHeader>>(profile.HttpRequestHeaders))
            {
                HttpHeaders += "ProfileHttpHeaderNames.Add(@\"" + this.FormatForVerbatimString(header.Name) + "\");\n";
                HttpHeaders += "ProfileHttpHeaderValues.Add(@\"" + this.FormatForVerbatimString(header.Value) + "\");\n";
            }
            string HttpUrls = "";
            foreach (string url in JsonConvert.DeserializeObject<List<string>>(profile.HttpUrls))
            {
                HttpUrls += "ProfileHttpUrls.Add(@\"" + this.FormatForVerbatimString(url) + "\");\n";
            }
            string HttpCookies = "";
            foreach (string cookie in JsonConvert.DeserializeObject<List<string>>(profile.HttpCookies))
            {
                HttpCookies += "ProfileHttpCookies.Add(@\"" + this.FormatForVerbatimString(cookie) + "\");\n";
            }

            return CodeTemplate
                .Replace("// {{REPLACE_PROFILE_HTTP_TRANSFORM}}", profile.HttpMessageTransform)
                .Replace("// {{REPLACE_PROFILE_HTTP_HEADERS}}", HttpHeaders)
                .Replace("// {{REPLACE_PROFILE_HTTP_URLS}}", HttpUrls)
                .Replace("// {{REPLACE_PROFILE_HTTP_COOKIES}}", HttpCookies)
                .Replace("{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}", this.FormatForVerbatimString(profile.HttpGetResponse))
                .Replace("{{REPLACE_PROFILE_HTTP_POST_REQUEST}}", this.FormatForVerbatimString(profile.HttpPostRequest))
                .Replace("{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}", this.FormatForVerbatimString(profile.HttpPostResponse))
                .Replace("{{REPLACE_COMM_TYPE}}", grunt.CommType.ToString())
                .Replace("{{REPLACE_VALIDATE_CERT}}", grunt.ValidateCert ? "true" : "false")
                .Replace("{{REPLACE_USE_CERT_PINNING}}", grunt.UseCertPinning ? "true" : "false")
                .Replace("{{REPLACE_PIPE_NAME}}", grunt.SMBPipeName)
                .Replace("{{REPLACE_COVENANT_URI}}", this.FormatForVerbatimString(ConnectUrl))
                .Replace("{{REPLACE_COVENANT_CERT_HASH}}", this.FormatForVerbatimString(this.UseSSL ? this.SSLCertHash : ""))
                .Replace("{{REPLACE_GRUNT_GUID}}", this.FormatForVerbatimString(grunt.OriginalServerGuid))
                .Replace("{{REPLACE_DELAY}}", this.FormatForVerbatimString(grunt.Delay.ToString()))
                .Replace("{{REPLACE_JITTER_PERCENT}}", this.FormatForVerbatimString(grunt.JitterPercent.ToString()))
                .Replace("{{REPLACE_CONNECT_ATTEMPTS}}", this.FormatForVerbatimString(grunt.ConnectAttempts.ToString()))
                .Replace("{{REPLACE_KILL_DATE}}", this.FormatForVerbatimString(grunt.KillDate.ToBinary().ToString()))
                .Replace("{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}", this.FormatForVerbatimString(grunt.GruntSharedSecretPassword));
        }

        private string FormatForVerbatimString(string replacement)
        {
            return replacement.Replace("\"", "\"\"").Replace("{", "{{").Replace("}", "}}").Replace("{{0}}", "{0}");
        }

        private static readonly string GruntStagerTemplateCode = File.ReadAllText(Path.Combine(Common.CovenantGruntDirectory, "GruntStager" + ".cs"));
        private static readonly string GruntExecutorTemplateCode = File.ReadAllText(Path.Combine(Common.CovenantGruntDirectory, "Grunt" + ".cs"));
    }

    public class HttpListenerContext : IdentityDbContext
    {
        public DbSet<HttpListener> Listener { get; set; }
        public HttpListenerContext(DbContextOptions<HttpListenerContext> options) : base(options)
        {

        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.Entity<HttpListener>().ToTable("HttpListener");
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
            services.AddTransient<ICovenantAPI, CovenantAPI>(api => {
                X509Certificate2 covenantCert = new X509Certificate2(Common.CovenantPublicCertFile);
                HttpClientHandler clientHandler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
                    {
                        return cert.GetCertHashString() == covenantCert.GetCertHashString();
                    }
                };
                return new CovenantAPI(
                    new Uri("https://localhost:7443"),
                    new Microsoft.Rest.TokenCredentials(Configuration["CovenantToken"]),
                    clientHandler
                );
            });
            services.AddDbContext<HttpListenerContext>(opt => opt.UseInMemoryDatabase("HttpListenerDatabase"));
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
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
             app.UseMvc(routes =>
            {
                foreach (string route in JsonConvert.DeserializeObject<List<string>>(Configuration["ProfileUrls"]))
                {
                    routes.MapRoute(route, route, new { controller = "HttpListener", action = "Get" });
                    routes.MapRoute(route + "Post", route, new { controller = "HttpListener", action = "Post" });
                }
            });

            var ContentTypeProvider = new FileExtensionContentTypeProvider(contentTypeMappings);
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(Common.CovenantStaticHostDirectory),
                RequestPath = "",
                ContentTypeProvider = ContentTypeProvider,
                ServeUnknownFileTypes = true,
                DefaultContentType = "text/plain"
            });
        }

        // Credit - https://github.com/samuelneff/MimeTypeMap
        private static IDictionary<string, string> contentTypeMappings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
                {".323", "text/h323"},
                {".3g2", "video/3gpp2"},
                {".3gp", "video/3gpp"},
                {".3gp2", "video/3gpp2"},
                {".3gpp", "video/3gpp"},
                {".7z", "application/x-7z-compressed"},
                {".aa", "audio/audible"},
                {".AAC", "audio/aac"},
                {".aaf", "application/octet-stream"},
                {".aax", "audio/vnd.audible.aax"},
                {".ac3", "audio/ac3"},
                {".aca", "application/octet-stream"},
                {".accda", "application/msaccess.addin"},
                {".accdb", "application/msaccess"},
                {".accdc", "application/msaccess.cab"},
                {".accde", "application/msaccess"},
                {".accdr", "application/msaccess.runtime"},
                {".accdt", "application/msaccess"},
                {".accdw", "application/msaccess.webapplication"},
                {".accft", "application/msaccess.ftemplate"},
                {".acx", "application/internet-property-stream"},
                {".AddIn", "text/xml"},
                {".ade", "application/msaccess"},
                {".adobebridge", "application/x-bridge-url"},
                {".adp", "application/msaccess"},
                {".ADT", "audio/vnd.dlna.adts"},
                {".ADTS", "audio/aac"},
                {".afm", "application/octet-stream"},
                {".ai", "application/postscript"},
                {".aif", "audio/aiff"},
                {".aifc", "audio/aiff"},
                {".aiff", "audio/aiff"},
                {".air", "application/vnd.adobe.air-application-installer-package+zip"},
                {".amc", "application/mpeg"},
                {".anx", "application/annodex"},
                {".apk", "application/vnd.android.package-archive" },
                {".application", "application/x-ms-application"},
                {".art", "image/x-jg"},
                {".asa", "application/xml"},
                {".asax", "application/xml"},
                {".ascx", "application/xml"},
                {".asd", "application/octet-stream"},
                {".asf", "video/x-ms-asf"},
                {".ashx", "application/xml"},
                {".asi", "application/octet-stream"},
                {".asm", "text/plain"},
                {".asmx", "application/xml"},
                {".aspx", "application/xml"},
                {".asr", "video/x-ms-asf"},
                {".asx", "video/x-ms-asf"},
                {".atom", "application/atom+xml"},
                {".au", "audio/basic"},
                {".avi", "video/x-msvideo"},
                {".axa", "audio/annodex"},
                {".axs", "application/olescript"},
                {".axv", "video/annodex"},
                {".bas", "text/plain"},
                {".bcpio", "application/x-bcpio"},
                {".bin", "application/octet-stream"},
                {".bmp", "image/bmp"},
                {".c", "text/plain"},
                {".cab", "application/octet-stream"},
                {".caf", "audio/x-caf"},
                {".calx", "application/vnd.ms-office.calx"},
                {".cat", "application/vnd.ms-pki.seccat"},
                {".cc", "text/plain"},
                {".cd", "text/plain"},
                {".cdda", "audio/aiff"},
                {".cdf", "application/x-cdf"},
                {".cer", "application/x-x509-ca-cert"},
                {".cfg", "text/plain"},
                {".chm", "application/octet-stream"},
                {".class", "application/x-java-applet"},
                {".clp", "application/x-msclip"},
                {".cmd", "text/plain"},
                {".cmx", "image/x-cmx"},
                {".cnf", "text/plain"},
                {".cod", "image/cis-cod"},
                {".config", "application/xml"},
                {".contact", "text/x-ms-contact"},
                {".coverage", "application/xml"},
                {".cpio", "application/x-cpio"},
                {".cpp", "text/plain"},
                {".crd", "application/x-mscardfile"},
                {".crl", "application/pkix-crl"},
                {".crt", "application/x-x509-ca-cert"},
                {".cs", "text/plain"},
                {".csdproj", "text/plain"},
                {".csh", "application/x-csh"},
                {".csproj", "text/plain"},
                {".css", "text/css"},
                {".csv", "text/csv"},
                {".cur", "application/octet-stream"},
                {".cxx", "text/plain"},
                {".dat", "application/octet-stream"},
                {".datasource", "application/xml"},
                {".dbproj", "text/plain"},
                {".dcr", "application/x-director"},
                {".def", "text/plain"},
                {".deploy", "application/octet-stream"},
                {".der", "application/x-x509-ca-cert"},
                {".dgml", "application/xml"},
                {".dib", "image/bmp"},
                {".dif", "video/x-dv"},
                {".dir", "application/x-director"},
                {".disco", "text/xml"},
                {".divx", "video/divx"},
                {".dll", "application/x-msdownload"},
                {".dll.config", "text/xml"},
                {".dlm", "text/dlm"},
                {".doc", "application/msword"},
                {".docm", "application/vnd.ms-word.document.macroEnabled.12"},
                {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
                {".dot", "application/msword"},
                {".dotm", "application/vnd.ms-word.template.macroEnabled.12"},
                {".dotx", "application/vnd.openxmlformats-officedocument.wordprocessingml.template"},
                {".dsp", "application/octet-stream"},
                {".dsw", "text/plain"},
                {".dtd", "text/xml"},
                {".dtsConfig", "text/xml"},
                {".dv", "video/x-dv"},
                {".dvi", "application/x-dvi"},
                {".dwf", "drawing/x-dwf"},
                {".dwp", "application/octet-stream"},
                {".dxr", "application/x-director"},
                {".eml", "message/rfc822"},
                {".emz", "application/octet-stream"},
                {".eot", "application/vnd.ms-fontobject"},
                {".eps", "application/postscript"},
                {".etl", "application/etl"},
                {".etx", "text/x-setext"},
                {".evy", "application/envoy"},
                {".exe", "application/octet-stream"},
                {".exe.config", "text/xml"},
                {".fdf", "application/vnd.fdf"},
                {".fif", "application/fractals"},
                {".filters", "application/xml"},
                {".fla", "application/octet-stream"},
                {".flac", "audio/flac"},
                {".flr", "x-world/x-vrml"},
                {".flv", "video/x-flv"},
                {".fsscript", "application/fsharp-script"},
                {".fsx", "application/fsharp-script"},
                {".generictest", "application/xml"},
                {".gif", "image/gif"},
                {".gpx", "application/gpx+xml"},
                {".group", "text/x-ms-group"},
                {".gsm", "audio/x-gsm"},
                {".gtar", "application/x-gtar"},
                {".gz", "application/x-gzip"},
                {".h", "text/plain"},
                {".hdf", "application/x-hdf"},
                {".hdml", "text/x-hdml"},
                {".hhc", "application/x-oleobject"},
                {".hhk", "application/octet-stream"},
                {".hhp", "application/octet-stream"},
                {".hlp", "application/winhlp"},
                {".hpp", "text/plain"},
                {".hqx", "application/mac-binhex40"},
                {".hta", "application/hta"},
                {".htc", "text/x-component"},
                {".htm", "text/html"},
                {".html", "text/html"},
                {".htt", "text/webviewhtml"},
                {".hxa", "application/xml"},
                {".hxc", "application/xml"},
                {".hxd", "application/octet-stream"},
                {".hxe", "application/xml"},
                {".hxf", "application/xml"},
                {".hxh", "application/octet-stream"},
                {".hxi", "application/octet-stream"},
                {".hxk", "application/xml"},
                {".hxq", "application/octet-stream"},
                {".hxr", "application/octet-stream"},
                {".hxs", "application/octet-stream"},
                {".hxt", "text/html"},
                {".hxv", "application/xml"},
                {".hxw", "application/octet-stream"},
                {".hxx", "text/plain"},
                {".i", "text/plain"},
                {".ico", "image/x-icon"},
                {".ics", "application/octet-stream"},
                {".idl", "text/plain"},
                {".ief", "image/ief"},
                {".iii", "application/x-iphone"},
                {".inc", "text/plain"},
                {".inf", "application/octet-stream"},
                {".ini", "text/plain"},
                {".inl", "text/plain"},
                {".ins", "application/x-internet-signup"},
                {".ipa", "application/x-itunes-ipa"},
                {".ipg", "application/x-itunes-ipg"},
                {".ipproj", "text/plain"},
                {".ipsw", "application/x-itunes-ipsw"},
                {".iqy", "text/x-ms-iqy"},
                {".isp", "application/x-internet-signup"},
                {".ite", "application/x-itunes-ite"},
                {".itlp", "application/x-itunes-itlp"},
                {".itms", "application/x-itunes-itms"},
                {".itpc", "application/x-itunes-itpc"},
                {".IVF", "video/x-ivf"},
                {".jar", "application/java-archive"},
                {".java", "application/octet-stream"},
                {".jck", "application/liquidmotion"},
                {".jcz", "application/liquidmotion"},
                {".jfif", "image/pjpeg"},
                {".jnlp", "application/x-java-jnlp-file"},
                {".jpb", "application/octet-stream"},
                {".jpe", "image/jpeg"},
                {".jpeg", "image/jpeg"},
                {".jpg", "image/jpeg"},
                {".js", "application/javascript"},
                {".json", "application/json"},
                {".jsx", "text/jscript"},
                {".jsxbin", "text/plain"},
                {".latex", "application/x-latex"},
                {".library-ms", "application/windows-library+xml"},
                {".lit", "application/x-ms-reader"},
                {".loadtest", "application/xml"},
                {".lpk", "application/octet-stream"},
                {".lsf", "video/x-la-asf"},
                {".lst", "text/plain"},
                {".lsx", "video/x-la-asf"},
                {".lzh", "application/octet-stream"},
                {".m13", "application/x-msmediaview"},
                {".m14", "application/x-msmediaview"},
                {".m1v", "video/mpeg"},
                {".m2t", "video/vnd.dlna.mpeg-tts"},
                {".m2ts", "video/vnd.dlna.mpeg-tts"},
                {".m2v", "video/mpeg"},
                {".m3u", "audio/x-mpegurl"},
                {".m3u8", "audio/x-mpegurl"},
                {".m4a", "audio/m4a"},
                {".m4b", "audio/m4b"},
                {".m4p", "audio/m4p"},
                {".m4r", "audio/x-m4r"},
                {".m4v", "video/x-m4v"},
                {".mac", "image/x-macpaint"},
                {".mak", "text/plain"},
                {".man", "application/x-troff-man"},
                {".manifest", "application/x-ms-manifest"},
                {".map", "text/plain"},
                {".master", "application/xml"},
                {".mda", "application/msaccess"},
                {".mdb", "application/x-msaccess"},
                {".mde", "application/msaccess"},
                {".mdp", "application/octet-stream"},
                {".me", "application/x-troff-me"},
                {".mfp", "application/x-shockwave-flash"},
                {".mht", "message/rfc822"},
                {".mhtml", "message/rfc822"},
                {".mid", "audio/mid"},
                {".midi", "audio/mid"},
                {".mix", "application/octet-stream"},
                {".mk", "text/plain"},
                {".mmf", "application/x-smaf"},
                {".mno", "text/xml"},
                {".mny", "application/x-msmoney"},
                {".mod", "video/mpeg"},
                {".mov", "video/quicktime"},
                {".movie", "video/x-sgi-movie"},
                {".mp2", "video/mpeg"},
                {".mp2v", "video/mpeg"},
                {".mp3", "audio/mpeg"},
                {".mp4", "video/mp4"},
                {".mp4v", "video/mp4"},
                {".mpa", "video/mpeg"},
                {".mpe", "video/mpeg"},
                {".mpeg", "video/mpeg"},
                {".mpf", "application/vnd.ms-mediapackage"},
                {".mpg", "video/mpeg"},
                {".mpp", "application/vnd.ms-project"},
                {".mpv2", "video/mpeg"},
                {".mqv", "video/quicktime"},
                {".ms", "application/x-troff-ms"},
                {".msi", "application/octet-stream"},
                {".mso", "application/octet-stream"},
                {".mts", "video/vnd.dlna.mpeg-tts"},
                {".mtx", "application/xml"},
                {".mvb", "application/x-msmediaview"},
                {".mvc", "application/x-miva-compiled"},
                {".mxp", "application/x-mmxp"},
                {".nc", "application/x-netcdf"},
                {".nsc", "video/x-ms-asf"},
                {".nws", "message/rfc822"},
                {".ocx", "application/octet-stream"},
                {".oda", "application/oda"},
                {".odb", "application/vnd.oasis.opendocument.database"},
                {".odc", "application/vnd.oasis.opendocument.chart"},
                {".odf", "application/vnd.oasis.opendocument.formula"},
                {".odg", "application/vnd.oasis.opendocument.graphics"},
                {".odh", "text/plain"},
                {".odi", "application/vnd.oasis.opendocument.image"},
                {".odl", "text/plain"},
                {".odm", "application/vnd.oasis.opendocument.text-master"},
                {".odp", "application/vnd.oasis.opendocument.presentation"},
                {".ods", "application/vnd.oasis.opendocument.spreadsheet"},
                {".odt", "application/vnd.oasis.opendocument.text"},
                {".oga", "audio/ogg"},
                {".ogg", "audio/ogg"},
                {".ogv", "video/ogg"},
                {".ogx", "application/ogg"},
                {".one", "application/onenote"},
                {".onea", "application/onenote"},
                {".onepkg", "application/onenote"},
                {".onetmp", "application/onenote"},
                {".onetoc", "application/onenote"},
                {".onetoc2", "application/onenote"},
                {".opus", "audio/ogg"},
                {".orderedtest", "application/xml"},
                {".osdx", "application/opensearchdescription+xml"},
                {".otf", "application/font-sfnt"},
                {".otg", "application/vnd.oasis.opendocument.graphics-template"},
                {".oth", "application/vnd.oasis.opendocument.text-web"},
                {".otp", "application/vnd.oasis.opendocument.presentation-template"},
                {".ots", "application/vnd.oasis.opendocument.spreadsheet-template"},
                {".ott", "application/vnd.oasis.opendocument.text-template"},
                {".oxt", "application/vnd.openofficeorg.extension"},
                {".p10", "application/pkcs10"},
                {".p12", "application/x-pkcs12"},
                {".p7b", "application/x-pkcs7-certificates"},
                {".p7c", "application/pkcs7-mime"},
                {".p7m", "application/pkcs7-mime"},
                {".p7r", "application/x-pkcs7-certreqresp"},
                {".p7s", "application/pkcs7-signature"},
                {".pbm", "image/x-portable-bitmap"},
                {".pcast", "application/x-podcast"},
                {".pct", "image/pict"},
                {".pcx", "application/octet-stream"},
                {".pcz", "application/octet-stream"},
                {".pdf", "application/pdf"},
                {".pfb", "application/octet-stream"},
                {".pfm", "application/octet-stream"},
                {".pfx", "application/x-pkcs12"},
                {".pgm", "image/x-portable-graymap"},
                {".pic", "image/pict"},
                {".pict", "image/pict"},
                {".pkgdef", "text/plain"},
                {".pkgundef", "text/plain"},
                {".pko", "application/vnd.ms-pki.pko"},
                {".pls", "audio/scpls"},
                {".pma", "application/x-perfmon"},
                {".pmc", "application/x-perfmon"},
                {".pml", "application/x-perfmon"},
                {".pmr", "application/x-perfmon"},
                {".pmw", "application/x-perfmon"},
                {".png", "image/png"},
                {".pnm", "image/x-portable-anymap"},
                {".pnt", "image/x-macpaint"},
                {".pntg", "image/x-macpaint"},
                {".pnz", "image/png"},
                {".pot", "application/vnd.ms-powerpoint"},
                {".potm", "application/vnd.ms-powerpoint.template.macroEnabled.12"},
                {".potx", "application/vnd.openxmlformats-officedocument.presentationml.template"},
                {".ppa", "application/vnd.ms-powerpoint"},
                {".ppam", "application/vnd.ms-powerpoint.addin.macroEnabled.12"},
                {".ppm", "image/x-portable-pixmap"},
                {".pps", "application/vnd.ms-powerpoint"},
                {".ppsm", "application/vnd.ms-powerpoint.slideshow.macroEnabled.12"},
                {".ppsx", "application/vnd.openxmlformats-officedocument.presentationml.slideshow"},
                {".ppt", "application/vnd.ms-powerpoint"},
                {".pptm", "application/vnd.ms-powerpoint.presentation.macroEnabled.12"},
                {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
                {".prf", "application/pics-rules"},
                {".prm", "application/octet-stream"},
                {".prx", "application/octet-stream"},
                {".ps", "application/postscript"},
                {".psc1", "application/PowerShell"},
                {".psd", "application/octet-stream"},
                {".psess", "application/xml"},
                {".psm", "application/octet-stream"},
                {".psp", "application/octet-stream"},
                {".pub", "application/x-mspublisher"},
                {".pwz", "application/vnd.ms-powerpoint"},
                {".qht", "text/x-html-insertion"},
                {".qhtm", "text/x-html-insertion"},
                {".qt", "video/quicktime"},
                {".qti", "image/x-quicktime"},
                {".qtif", "image/x-quicktime"},
                {".qtl", "application/x-quicktimeplayer"},
                {".qxd", "application/octet-stream"},
                {".ra", "audio/x-pn-realaudio"},
                {".ram", "audio/x-pn-realaudio"},
                {".rar", "application/x-rar-compressed"},
                {".ras", "image/x-cmu-raster"},
                {".rat", "application/rat-file"},
                {".rc", "text/plain"},
                {".rc2", "text/plain"},
                {".rct", "text/plain"},
                {".rdlc", "application/xml"},
                {".reg", "text/plain"},
                {".resx", "application/xml"},
                {".rf", "image/vnd.rn-realflash"},
                {".rgb", "image/x-rgb"},
                {".rgs", "text/plain"},
                {".rm", "application/vnd.rn-realmedia"},
                {".rmi", "audio/mid"},
                {".rmp", "application/vnd.rn-rn_music_package"},
                {".roff", "application/x-troff"},
                {".rpm", "audio/x-pn-realaudio-plugin"},
                {".rqy", "text/x-ms-rqy"},
                {".rtf", "application/rtf"},
                {".rtx", "text/richtext"},
                {".ruleset", "application/xml"},
                {".s", "text/plain"},
                {".safariextz", "application/x-safari-safariextz"},
                {".scd", "application/x-msschedule"},
                {".scr", "text/plain"},
                {".sct", "text/scriptlet"},
                {".sd2", "audio/x-sd2"},
                {".sdp", "application/sdp"},
                {".sea", "application/octet-stream"},
                {".searchConnector-ms", "application/windows-search-connector+xml"},
                {".setpay", "application/set-payment-initiation"},
                {".setreg", "application/set-registration-initiation"},
                {".settings", "application/xml"},
                {".sgimb", "application/x-sgimb"},
                {".sgml", "text/sgml"},
                {".sh", "application/x-sh"},
                {".shar", "application/x-shar"},
                {".shtml", "text/html"},
                {".sit", "application/x-stuffit"},
                {".sitemap", "application/xml"},
                {".skin", "application/xml"},
                {".sldm", "application/vnd.ms-powerpoint.slide.macroEnabled.12"},
                {".sldx", "application/vnd.openxmlformats-officedocument.presentationml.slide"},
                {".slk", "application/vnd.ms-excel"},
                {".sln", "text/plain"},
                {".slupkg-ms", "application/x-ms-license"},
                {".smd", "audio/x-smd"},
                {".smi", "application/octet-stream"},
                {".smx", "audio/x-smd"},
                {".smz", "audio/x-smd"},
                {".snd", "audio/basic"},
                {".snippet", "application/xml"},
                {".snp", "application/octet-stream"},
                {".sol", "text/plain"},
                {".sor", "text/plain"},
                {".spc", "application/x-pkcs7-certificates"},
                {".spl", "application/futuresplash"},
                {".spx", "audio/ogg"},
                {".src", "application/x-wais-source"},
                {".srf", "text/plain"},
                {".SSISDeploymentManifest", "text/xml"},
                {".ssm", "application/streamingmedia"},
                {".sst", "application/vnd.ms-pki.certstore"},
                {".stl", "application/vnd.ms-pki.stl"},
                {".sv4cpio", "application/x-sv4cpio"},
                {".sv4crc", "application/x-sv4crc"},
                {".svc", "application/xml"},
                {".svg", "image/svg+xml"},
                {".swf", "application/x-shockwave-flash"},
                {".step", "application/step"},
                {".stp", "application/step"},
                {".t", "application/x-troff"},
                {".tar", "application/x-tar"},
                {".tcl", "application/x-tcl"},
                {".testrunconfig", "application/xml"},
                {".testsettings", "application/xml"},
                {".tex", "application/x-tex"},
                {".texi", "application/x-texinfo"},
                {".texinfo", "application/x-texinfo"},
                {".tgz", "application/x-compressed"},
                {".thmx", "application/vnd.ms-officetheme"},
                {".thn", "application/octet-stream"},
                {".tif", "image/tiff"},
                {".tiff", "image/tiff"},
                {".tlh", "text/plain"},
                {".tli", "text/plain"},
                {".toc", "application/octet-stream"},
                {".tr", "application/x-troff"},
                {".trm", "application/x-msterminal"},
                {".trx", "application/xml"},
                {".ts", "video/vnd.dlna.mpeg-tts"},
                {".tsv", "text/tab-separated-values"},
                {".ttf", "application/font-sfnt"},
                {".tts", "video/vnd.dlna.mpeg-tts"},
                {".txt", "text/plain"},
                {".u32", "application/octet-stream"},
                {".uls", "text/iuls"},
                {".user", "text/plain"},
                {".ustar", "application/x-ustar"},
                {".vb", "text/plain"},
                {".vbdproj", "text/plain"},
                {".vbk", "video/mpeg"},
                {".vbproj", "text/plain"},
                {".vbs", "text/vbscript"},
                {".vcf", "text/x-vcard"},
                {".vcproj", "application/xml"},
                {".vcs", "text/plain"},
                {".vcxproj", "application/xml"},
                {".vddproj", "text/plain"},
                {".vdp", "text/plain"},
                {".vdproj", "text/plain"},
                {".vdx", "application/vnd.ms-visio.viewer"},
                {".vml", "text/xml"},
                {".vscontent", "application/xml"},
                {".vsct", "text/xml"},
                {".vsd", "application/vnd.visio"},
                {".vsi", "application/ms-vsi"},
                {".vsix", "application/vsix"},
                {".vsixlangpack", "text/xml"},
                {".vsixmanifest", "text/xml"},
                {".vsmdi", "application/xml"},
                {".vspscc", "text/plain"},
                {".vss", "application/vnd.visio"},
                {".vsscc", "text/plain"},
                {".vssettings", "text/xml"},
                {".vssscc", "text/plain"},
                {".vst", "application/vnd.visio"},
                {".vstemplate", "text/xml"},
                {".vsto", "application/x-ms-vsto"},
                {".vsw", "application/vnd.visio"},
                {".vsx", "application/vnd.visio"},
                {".vtx", "application/vnd.visio"},
                {".wav", "audio/wav"},
                {".wave", "audio/wav"},
                {".wax", "audio/x-ms-wax"},
                {".wbk", "application/msword"},
                {".wbmp", "image/vnd.wap.wbmp"},
                {".wcm", "application/vnd.ms-works"},
                {".wdb", "application/vnd.ms-works"},
                {".wdp", "image/vnd.ms-photo"},
                {".webarchive", "application/x-safari-webarchive"},
                {".webm", "video/webm"},
                {".webp", "image/webp"}, /* https://en.wikipedia.org/wiki/WebP */                {".webtest", "application/xml"},
                {".wiq", "application/xml"},
                {".wiz", "application/msword"},
                {".wks", "application/vnd.ms-works"},
                {".WLMP", "application/wlmoviemaker"},
                {".wlpginstall", "application/x-wlpg-detect"},
                {".wlpginstall3", "application/x-wlpg3-detect"},
                {".wm", "video/x-ms-wm"},
                {".wma", "audio/x-ms-wma"},
                {".wmd", "application/x-ms-wmd"},
                {".wmf", "application/x-msmetafile"},
                {".wml", "text/vnd.wap.wml"},
                {".wmlc", "application/vnd.wap.wmlc"},
                {".wmls", "text/vnd.wap.wmlscript"},
                {".wmlsc", "application/vnd.wap.wmlscriptc"},
                {".wmp", "video/x-ms-wmp"},
                {".wmv", "video/x-ms-wmv"},
                {".wmx", "video/x-ms-wmx"},
                {".wmz", "application/x-ms-wmz"},
                {".woff", "application/font-woff"},
                {".wpl", "application/vnd.ms-wpl"},
                {".wps", "application/vnd.ms-works"},
                {".wri", "application/x-mswrite"},
                {".wrl", "x-world/x-vrml"},
                {".wrz", "x-world/x-vrml"},
                {".wsc", "text/scriptlet"},
                {".wsdl", "text/xml"},
                {".wvx", "video/x-ms-wvx"},
                {".x", "application/directx"},
                {".xaf", "x-world/x-vrml"},
                {".xaml", "application/xaml+xml"},
                {".xap", "application/x-silverlight-app"},
                {".xbap", "application/x-ms-xbap"},
                {".xbm", "image/x-xbitmap"},
                {".xdr", "text/plain"},
                {".xht", "application/xhtml+xml"},
                {".xhtml", "application/xhtml+xml"},
                {".xla", "application/vnd.ms-excel"},
                {".xlam", "application/vnd.ms-excel.addin.macroEnabled.12"},
                {".xlc", "application/vnd.ms-excel"},
                {".xld", "application/vnd.ms-excel"},
                {".xlk", "application/vnd.ms-excel"},
                {".xll", "application/vnd.ms-excel"},
                {".xlm", "application/vnd.ms-excel"},
                {".xls", "application/vnd.ms-excel"},
                {".xlsb", "application/vnd.ms-excel.sheet.binary.macroEnabled.12"},
                {".xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12"},
                {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
                {".xlt", "application/vnd.ms-excel"},
                {".xltm", "application/vnd.ms-excel.template.macroEnabled.12"},
                {".xltx", "application/vnd.openxmlformats-officedocument.spreadsheetml.template"},
                {".xlw", "application/vnd.ms-excel"},
                {".xml", "text/xml"},
                {".xmta", "application/xml"},
                {".xof", "x-world/x-vrml"},
                {".XOML", "text/plain"},
                {".xpm", "image/x-xpixmap"},
                {".xps", "application/vnd.ms-xpsdocument"},
                {".xrm-ms", "text/xml"},
                {".xsc", "application/xml"},
                {".xsd", "text/xml"},
                {".xsf", "text/xml"},
                {".xsl", "text/xml"},
                {".xslt", "text/xml"},
                {".xsn", "application/octet-stream"},
                {".xss", "application/xml"},
                {".xspf", "application/xspf+xml"},
                {".xtp", "application/octet-stream"},
                {".xwd", "image/x-xwindowdump"},
                {".z", "application/x-compress"},
                {".zip", "application/zip"},

                {"application/fsharp-script", ".fsx"},
                {"application/msaccess", ".adp"},
                {"application/msword", ".doc"},
                {"application/octet-stream", ".bin"},
                {"application/onenote", ".one"},
                {"application/postscript", ".eps"},
                {"application/step", ".step"},
                {"application/vnd.ms-excel", ".xls"},
                {"application/vnd.ms-powerpoint", ".ppt"},
                {"application/vnd.ms-works", ".wks"},
                {"application/vnd.visio", ".vsd"},
                {"application/x-director", ".dir"},
                {"application/x-shockwave-flash", ".swf"},
                {"application/x-x509-ca-cert", ".cer"},
                {"application/x-zip-compressed", ".zip"},
                {"application/xhtml+xml", ".xhtml"},
                {"application/xml", ".xml"},  // anomoly, .xml -> text/xml, but application/xml -> many thingss, but all are xml, so safest is .xml
                {"audio/aac", ".AAC"},
                {"audio/aiff", ".aiff"},
                {"audio/basic", ".snd"},
                {"audio/mid", ".midi"},
                {"audio/wav", ".wav"},
                {"audio/x-m4a", ".m4a"},
                {"audio/x-mpegurl", ".m3u"},
                {"audio/x-pn-realaudio", ".ra"},
                {"audio/x-smd", ".smd"},
                {"image/bmp", ".bmp"},
                {"image/jpeg", ".jpg"},
                {"image/pict", ".pic"},
                {"image/png", ".png"},
                {"image/tiff", ".tiff"},
                {"image/x-macpaint", ".mac"},
                {"image/x-quicktime", ".qti"},
                {"message/rfc822", ".eml"},
                {"text/html", ".html"},
                {"text/plain", ".txt"},
                {"text/scriptlet", ".wsc"},
                {"text/xml", ".xml"},
                {"video/3gpp", ".3gp"},
                {"video/3gpp2", ".3gp2"},
                {"video/mp4", ".mp4"},
                {"video/mpeg", ".mpg"},
                {"video/quicktime", ".mov"},
                {"video/vnd.dlna.mpeg-tts", ".m2t"},
                {"video/x-dv", ".dv"},
                {"video/x-la-asf", ".lsf"},
                {"video/x-ms-asf", ".asf"},
                {"x-world/x-vrml", ".xof"},
        };
    }
}

// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Threading;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using McMaster.Extensions.CommandLineUtils;
using NLog.Web;
using NLog.Config;
using NLog.Targets;

using Covenant.Models;
using Covenant.Core;
using Covenant.Models.Covenant;

namespace Covenant
{
    public class Program
    {
        static void Main(string[] args)
        {
            CommandLineApplication app = new CommandLineApplication();
            app.HelpOption("-? | -h | --help");
            var UserNameOption = app.Option(
                "-u | --username <USERNAME>",
                "The UserName to login to the Covenant API.",
                CommandOptionType.SingleValue
            );
            var PasswordOption = app.Option(
                "-p | --password <PASSWORD>",
                "The Password to login to the Covenant API.",
                CommandOptionType.SingleValue
            );
            var ComputerNameOption = app.Option(
                "-c | --computername <COMPUTERNAME>",
                "The ComputerName (IPAddress or Hostname) to bind the Covenant API to.",
                CommandOptionType.SingleValue
            );

            app.OnExecute(() =>
            {
                if (!File.Exists(Path.Combine(Common.CovenantSharpSploitDirectory, "README.md")) ||
                    !File.Exists(Path.Combine(Common.CovenantRubeusDirectory, "README.md")))
                {
                    Console.Error.WriteLine("Error: git submodules have not been initialized");
                    Console.Error.WriteLine("Covenant's submodules can be cloned with: git clone --recurse-submodules https://github.com/cobbr/Covenant");
                    Console.Error.WriteLine("Or initialized after cloning with: git submodule update --init --recursive");
                    return -1;
                }

                string username = UserNameOption.Value();
                string password = PasswordOption.Value();
                if (!UserNameOption.HasValue())
                {
                    Console.Write("Username: ");
                    username = Console.ReadLine();
                }
                if (!PasswordOption.HasValue())
                {
                    Console.Write("Password: ");
                    password = GetPassword();
                    Console.WriteLine();
                }

                string CovenantBindUrl = ComputerNameOption.HasValue() ? ComputerNameOption.Value() : "0.0.0.0";
                IPAddress address = null;
                try
                {
                    address = IPAddress.Parse(CovenantBindUrl);
                }
                catch (FormatException)
                {
                    address = Dns.GetHostAddresses(CovenantBindUrl).FirstOrDefault();
                }
                IPEndPoint CovenantEndpoint = new IPEndPoint(address, Common.CovenantHTTPSPort);
                string CovenantUri = (CovenantBindUrl == "0.0.0.0" ? "https://127.0.0.1:" + Common.CovenantHTTPSPort : "https://" + CovenantEndpoint);
                var host = BuildWebHost(
                    CovenantEndpoint,
                    CovenantUri,
                    username,
                    password
                );
                using (var scope = host.Services.CreateScope())
                {
                    var services = scope.ServiceProvider;
                    var context = services.GetRequiredService<CovenantContext>();
                    var userManager = services.GetRequiredService<UserManager<CovenantUser>>();
					var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
                    var configuration = services.GetRequiredService<IConfiguration>();
					var cancellationTokens = services.GetRequiredService<Dictionary<int, CancellationTokenSource>>();
                    DbInitializer.Initialize(context, userManager, roleManager, configuration, cancellationTokens);
                }
                
                LoggingConfiguration loggingConfig = new LoggingConfiguration();
                var consoleTarget = new ColoredConsoleTarget();
                var fileTarget = new FileTarget();
                loggingConfig.AddTarget("console", consoleTarget);
                loggingConfig.AddTarget("file", fileTarget);
                consoleTarget.Layout = @"${longdate}|${event-properties:item=EventId_Id}|${uppercase:${level}}|${logger}|${message} ${exception:format=tostring}";
                fileTarget.Layout = @"${longdate}|${event-properties:item=EventId_Id}|${uppercase:${level}}|${logger}|${message} ${exception:format=tostring}";
                fileTarget.FileName = Common.CovenantLogDirectory + "covenant.log";
                loggingConfig.AddRule(NLog.LogLevel.Info, NLog.LogLevel.Fatal, "console");
                loggingConfig.AddRule(NLog.LogLevel.Info, NLog.LogLevel.Fatal, "file");

                var logger = NLogBuilder.ConfigureNLog(loggingConfig).GetCurrentClassLogger();
                try
                {
                    logger.Debug("Starting Covenant API");
                    host.Run();
                }
                catch (Exception ex)
                {
                    logger.Error(ex, "Covenant stopped due to exception");
                    throw;
                }
                finally
                {
                    NLog.LogManager.Shutdown();
                }
                return 0;
            });
            app.Execute(args);
        }

        public static IWebHost BuildWebHost(IPEndPoint CovenantEndpoint, string CovenantUri, string CovenantUsername, string CovenantPassword) =>
            new WebHostBuilder()
                .UseKestrel(options =>
                {
                    options.Listen(CovenantEndpoint, listenOptions =>
                    {
                        listenOptions.UseHttps(httpsOptions =>
                        {
                            if (!File.Exists(Common.CovenantPrivateCertFile) || !File.Exists(Common.CovenantPublicCertFile))
                            {
                                Console.WriteLine("Creating cert...");
                                X509Certificate2 certificate = Utilities.CreateSelfSignedCertificate(CovenantEndpoint.Address, "CN=Covenant");
                                File.WriteAllBytes(Common.CovenantPrivateCertFile, certificate.Export(X509ContentType.Pfx, CovenantPassword));
                                File.WriteAllBytes(Common.CovenantPublicCertFile, certificate.Export(X509ContentType.Cert));
                            }
                            try
                            {
                                httpsOptions.ServerCertificate = new X509Certificate2(Common.CovenantPrivateCertFile, CovenantPassword);
                            }
                            catch (CryptographicException)
                            {
                                Console.Error.WriteLine("Error importing Covenant certificate. Wrong password? Must use initial user/password.");
                            }
                            httpsOptions.SslProtocols = SslProtocols.Tls12;
                            Console.WriteLine("Using Covenant certificate with hash: " + httpsOptions.ServerCertificate.GetCertHashString());
                        });
                    });
                })
                .UseContentRoot(Directory.GetCurrentDirectory())
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    string appsettingscontents = File.ReadAllText(Common.CovenantAppSettingsFile);
                    if (appsettingscontents.Contains(Common.CovenantJwtKeyReplaceMessage))
                    {
                        Console.WriteLine("Found default JwtKey, replacing with auto-generated key...");
                        File.WriteAllText(Common.CovenantAppSettingsFile, appsettingscontents.Replace(Common.CovenantJwtKeyReplaceMessage, Utilities.GenerateJwtKey()));
                    }
                    var env = hostingContext.HostingEnvironment;
                    config.AddJsonFile(Common.CovenantAppSettingsFile, optional: false, reloadOnChange: false);
                    config.AddEnvironmentVariables();
                })
                .ConfigureLogging((hostingContext, logging) =>
                {
                    logging.ClearProviders();
                    logging.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
                    logging.AddConsole();
                    logging.AddDebug();
                    logging.AddFilter("System", LogLevel.Warning)
                           .AddFilter("Microsoft", LogLevel.Warning);
                })
                .UseStartup<Startup>()
                .UseSetting("CovenantUri", CovenantUri)
                .UseSetting("CovenantUsername", CovenantUsername)
                .UseSetting("CovenantPassword", CovenantPassword)
                .Build();

        private static string GetPassword()
        {
            string password = "";
            ConsoleKeyInfo nextKey = Console.ReadKey(true);
            while (nextKey.Key != ConsoleKey.Enter)
            {
                if (nextKey.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password = password.Substring(0, password.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    password += nextKey.KeyChar;
                    Console.Write("*");
                }
                nextKey = Console.ReadKey(true);
            }
            return password;
        }
    }
}

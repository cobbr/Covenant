using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Rest;
using Microsoft.Extensions.Configuration;

using Covenant.API;
using Covenant.Models.Listeners;

namespace Covenant.Core
{
    public class CovenantAPIService
    {
        private readonly HttpClientHandler _handler;
        private readonly IConfiguration _configuration;

        public CovenantAPIService(IConfiguration configuration)
        {
            _configuration = configuration;
            X509Certificate2 covenantCert = new X509Certificate2(Common.CovenantPublicCertFile);
            _handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
                {
                    return cert.GetCertHashString() == covenantCert.GetCertHashString();
                }
            };
        }

        public async Task CreateHttpListener(HttpListener listener, string token)
        {
            CovenantAPI client = new CovenantAPI(
                new Uri("https://localhost:" + _configuration["CovenantPort"]),
                new TokenCredentials(token),
                _handler
            );
            await client.CreateHttpListenerAsync(ToAPIListener(listener));
        }

        public async Task CreateBridgeListener(BridgeListener listener, string token)
        {
            CovenantAPI client = new CovenantAPI(
                new Uri("https://localhost:" + _configuration["CovenantPort"]),
                new TokenCredentials(token),
                _handler
            );
            await client.CreateBridgeListenerAsync(ToAPIListener(listener));
        }

        public async Task EditHttpListener(HttpListener listener, string token)
        {
            CovenantAPI client = new CovenantAPI(
                new Uri("https://localhost:" + _configuration["CovenantPort"]),
                new TokenCredentials(token),
                _handler
            );
            await client.EditHttpListenerAsync(ToAPIListener(listener));
        }

        public async Task EditBridgeListener(BridgeListener listener, string token)
        {
            CovenantAPI client = new CovenantAPI(
                new Uri("https://localhost:" + _configuration["CovenantPort"]),
                new TokenCredentials(token),
                _handler
            );
            await client.EditBridgeListenerAsync(ToAPIListener(listener));
        }

        public static Covenant.API.Models.HttpListener ToAPIListener(HttpListener listener)
        {
            return new Covenant.API.Models.HttpListener
            {
                Id = listener.Id,
                Name = listener.Name,
                BindAddress = listener.BindAddress,
                BindPort = listener.BindPort,
                ConnectAddresses = listener.ConnectAddresses,
                ConnectPort = listener.ConnectPort,
                CovenantUrl = listener.CovenantUrl,
                CovenantToken = listener.CovenantToken,
                Description = listener.Description,
                Guid = listener.GUID,
                ListenerTypeId = listener.ListenerTypeId,
                ProfileId = listener.ProfileId,
                SslCertHash = listener.SSLCertHash,
                SslCertificate = listener.SSLCertificate,
                SslCertificatePassword = listener.SSLCertificatePassword,
                StartTime = listener.StartTime,
                Status = (Covenant.API.Models.ListenerStatus)Enum.Parse(typeof(Covenant.API.Models.ListenerStatus), listener.Status.ToString(), true),
                Urls = listener.Urls,
                UseSSL = listener.UseSSL
            };
        }

        public static Covenant.API.Models.BridgeListener ToAPIListener(BridgeListener listener)
        {
            return new Covenant.API.Models.BridgeListener
            {
                Id = listener.Id,
                Name = listener.Name,
                BindAddress = listener.BindAddress,
                BindPort = listener.BindPort,
                ConnectAddresses = listener.ConnectAddresses,
                ConnectPort = listener.ConnectPort,
                CovenantUrl = listener.CovenantUrl,
                CovenantToken = listener.CovenantToken,
                Description = listener.Description,
                Guid = listener.GUID,
                IsBridgeConnected = listener.IsBridgeConnected,
                ImplantReadCode = listener.ImplantReadCode,
                ImplantWriteCode = listener.ImplantWriteCode,
                ListenerTypeId = listener.ListenerTypeId,
                ProfileId = listener.ProfileId,
                StartTime = listener.StartTime,
                Status = (Covenant.API.Models.ListenerStatus)Enum.Parse(typeof(Covenant.API.Models.ListenerStatus), listener.Status.ToString(), true)
            };
        }
    }
}
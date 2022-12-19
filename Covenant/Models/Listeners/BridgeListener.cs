// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

using Covenant.Core;

namespace Covenant.Models.Listeners
{
    public class BridgeListener : Listener
    {
        public bool IsBridgeConnected { get; set; } = false;

        public string ImplantReadCode { get; set; }
        public string ImplantWriteCode { get; set; }

        private InternalListener InternalListener { get; set; }
        private readonly HashSet<string> _guids = new HashSet<string>();

        public BridgeListener()
        {
            this.Description = "A Bridge for custom listeners.";
        }

        public BridgeListener(int ListenerTypeId, int ProfileId) : this()
        {
            this.ListenerTypeId = ListenerTypeId;
            this.ProfileId = ProfileId;
            this.BindPort = 7444;
            this.ConnectPort = 7445;
            try
            {
                this.ConnectAddresses = new List<string>
                {
                    Dns.GetHostAddresses(Dns.GetHostName())
                        .FirstOrDefault(A => A.AddressFamily == AddressFamily.InterNetwork)
                        .ToString()
                };
            }
            catch (SocketException)
            {
                this.ConnectAddresses = new List<string> { "" };
            }
        }

        public BridgeListener(ListenerType type, Profile profile) : this(type.Id, profile.Id)
        {
            this.ListenerType = type;
            this.Profile = profile;
        }

        public override CancellationTokenSource Start()
        {
            this.InternalListener = new InternalListener();
            _ = this.InternalListener.Configure(InternalListener.ToProfile(this.Profile), this.GUID, this.CovenantUrl, this.CovenantToken);
            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
            Task.Run(() => this.Run(cancellationTokenSource.Token));
            return cancellationTokenSource;
        }

        public override void Stop(CancellationTokenSource cancellationTokenSource)
        {
            cancellationTokenSource.Cancel();
        }

        private async Task Run(CancellationToken token)
        {
            CancellationTokenSource clientSource = null;
            TcpListener listener = new TcpListener(IPAddress.Parse(this.BindAddress), this.BindPort);
            listener.Start();
            while (!token.IsCancellationRequested)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                client.ReceiveTimeout = 0;
                client.SendTimeout = 0;
                if (clientSource != null)
                {
                    clientSource.Cancel();
                    clientSource.Dispose();
                }
                clientSource = new CancellationTokenSource();
                this.IsBridgeConnected = true;
                _ = Task.Run(async () => await RunClient(client, clientSource.Token), clientSource.Token);
            }
            clientSource.Cancel();
            clientSource.Dispose();
        }

        private async Task RunClient(TcpClient client, CancellationToken token)
        {
            NetworkStream stream = client.GetStream();
            stream.ReadTimeout = Timeout.Infinite;
            stream.WriteTimeout = Timeout.Infinite;
            this.InternalListener.OnNewMessage += (sender, e) =>
            {
                _ = Task.Run(async () =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        try
                        {
                            string data = await this.InternalListener.Read(e.Guid);
                            this.IsBridgeConnected = true;
                            if (!string.IsNullOrEmpty(data))
                            {
                                string formatted = string.Format(((BridgeProfile)this.Profile).ReadFormat.Replace("{DATA}", "{0}").Replace("{GUID}", "{1}"), data, e.Guid);
                                this.NetworkWriteString(stream, formatted);
                            }
                            return;
                        }
                        catch (ControllerNotFoundException ex)
                        {
                            this.NetworkWriteString(stream, ex.Message);
                            return;
                        }
                        catch (Exception) { Thread.Sleep(5000); this.IsBridgeConnected = false; }
                    }
                });
            };
            while (!token.IsCancellationRequested)
            {
                string data = NetworkReadString(stream, token);
                if (data == null)
                {
                    return;
                }
                else
                {
                    List<string> parsed = data.ParseExact(((BridgeProfile)this.Profile).WriteFormat.Replace("{DATA}", "{0}").Replace("{GUID}", "{1}")).ToList();
                    if (parsed.Count == 2)
                    {
                        _guids.Add(parsed[1]);
                        await this.InternalListener.Write(parsed[1], parsed[0]);
                    }
                }
            }
        }

        private void NetworkWriteString(NetworkStream stream, string data)
        {
            if (!string.IsNullOrEmpty(data))
            {
                byte[] dataBytes = Common.CovenantEncoding.GetBytes(data);
                byte[] size = new byte[4];
                size[0] = (byte)(dataBytes.Length >> 24);
                size[1] = (byte)(dataBytes.Length >> 16);
                size[2] = (byte)(dataBytes.Length >> 8);
                size[3] = (byte)dataBytes.Length;
                stream.Write(size);
                int writtenBytes = 0;
                while (writtenBytes < dataBytes.Length)
                {
                    int bytesToWrite = Math.Min(dataBytes.Length - writtenBytes, 1024);
                    stream.Write(dataBytes, writtenBytes, bytesToWrite);
                    writtenBytes += bytesToWrite;
                }
            }
        }

        private string NetworkReadString(NetworkStream stream, CancellationToken token)
        {
            byte[] size = new byte[4];
            int totalReadBytes = 0;
            int readBytes;
            do
            {
                readBytes = stream.Read(size, totalReadBytes, size.Length - totalReadBytes);
                if (readBytes == 0) { return null; }
                totalReadBytes += readBytes;
            } while (totalReadBytes < size.Length);
            int len = (size[0] << 24) + (size[1] << 16) + (size[2] << 8) + size[3];
            byte[] buffer = new byte[1024];
            using (var ms = new MemoryStream())
            {
                totalReadBytes = 0;
                readBytes = 0;
                do
                {
                    readBytes = stream.Read(buffer, 0, buffer.Length);
                    if (readBytes == 0) { return null; }
                    ms.Write(buffer, 0, readBytes);
                    totalReadBytes += readBytes;
                } while (totalReadBytes < len);
                return Common.CovenantEncoding.GetString(ms.ToArray());
            }
        }
    }
}

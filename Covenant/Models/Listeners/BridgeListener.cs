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
        public bool IsBridgeConnected { get; set; }

        public string ImplantReadCode { get; set; }
        public string ImplantWriteCode { get; set; }

        private InternalListener InternalListener { get; set; }
        private readonly HashSet<string> _guids = new HashSet<string>();

        public BridgeListener()
        {
            this.Description = "A Bridge for custom listeners.";
            this.BindPort = 7444;
            this.IsBridgeConnected = false;
            try
            {
				this.ConnectAddresses = new List<string>
				{
					Dns.GetHostAddresses(Dns.GetHostName())
						.FirstOrDefault(A => A.AddressFamily == AddressFamily.InterNetwork)
						.ToString()
				};
            }
            catch (SocketException) { }
        }

        public BridgeListener(int ListenerTypeId, int ProfileId) : this()
        {
            this.ListenerTypeId = ListenerTypeId;
            this.ProfileId = ProfileId;
        }

        public override CancellationTokenSource Start()
        {
            this.InternalListener = new InternalListener();
            _ = this.InternalListener.Configure(InternalListener.ToProfile(this.Profile), this.GUID, this.CovenantToken);
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
                using (TcpClient client = await listener.AcceptTcpClientAsync())
                {
                    client.ReceiveTimeout = Timeout.Infinite;
                    if (clientSource != null)
                    {
                        clientSource.Cancel();
                        clientSource.Dispose();
                    }
                    clientSource = new CancellationTokenSource();
                    
                    _ = Task.Run(async () => await RunClient(client, token));
                }
            }
            clientSource.Cancel();
            clientSource.Dispose();
        }

        private async Task RunClient(TcpClient client, CancellationToken token)
        {
            NetworkStream stream = client.GetStream();
            stream.ReadTimeout = Timeout.Infinite;
            _ = Task.Run(() => _ = RunClientReadPoll(stream, token));
            while (!token.IsCancellationRequested)
            {
                string guid = NetworkReadString(stream, token);
                _guids.Add(guid);
                string data = NetworkReadString(stream, token);
                string ExtractedMessage = data.ParseExact(((BridgeProfile)this.Profile).WriteFormat).FirstOrDefault();
                await this.InternalListener.Write(guid, ExtractedMessage);
            }
        }

        private async Task RunClientReadPoll(NetworkStream stream, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                Thread.Sleep(10000);
                foreach(string guid in _guids)
                {
                    try
                    {
                        string data = await this.InternalListener.Read(guid);
                        string formatted = string.Format(((BridgeProfile)this.Profile).ReadFormat, data);
                        await this.NetworkWriteString(stream, guid, token);
                        await this.NetworkWriteString(stream, formatted, token);
                    }
                    catch { }
                }
            }
        }

        private async Task NetworkWriteString(NetworkStream stream, string data, CancellationToken token)
        {
            if (!string.IsNullOrEmpty(data))
            {
                byte[] dataBytes = Common.CovenantEncoding.GetBytes(data);
                byte[] size = new byte[4];
                size[0] = (byte)(dataBytes.Length >> 24);
                size[1] = (byte)(dataBytes.Length >> 16);
                size[2] = (byte)(dataBytes.Length >> 8);
                size[3] = (byte)dataBytes.Length;
                await stream.WriteAsync(dataBytes, token);
                int writtenBytes = 0;
                while (writtenBytes < dataBytes.Length)
                {
                    int bytesToWrite = Math.Min(dataBytes.Length - writtenBytes, 1024);
                    await stream.WriteAsync(dataBytes, writtenBytes, bytesToWrite, token);
                    writtenBytes += bytesToWrite;
                }
            }
        }

        private string NetworkReadString(NetworkStream stream, CancellationToken token)
        {
            byte[] size = new byte[4];
            int totalReadBytes = 0;
            do
            {
                totalReadBytes += stream.Read(size, totalReadBytes, size.Length - totalReadBytes);
            } while (totalReadBytes < size.Length);
            int len = (size[0] << 24) + (size[1] << 16) + (size[2] << 8) + size[3];

            byte[] buffer = new byte[1024];
            using (var ms = new MemoryStream())
            {
                totalReadBytes = 0;
                int readBytes = 0;
                do
                {
                    readBytes = stream.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, readBytes);
                    totalReadBytes += readBytes;
                } while (totalReadBytes < len);
                return Common.CovenantEncoding.GetString(ms.ToArray());
            }
        }
    }
}

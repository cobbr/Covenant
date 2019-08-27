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
                Console.WriteLine("Bridge Listener: waiting to accept client");
                TcpClient client = await listener.AcceptTcpClientAsync();
                client.ReceiveTimeout = 0;
                client.SendTimeout = 0;
                Console.WriteLine("Accepted client");
                if (clientSource != null)
                {
                    clientSource.Cancel();
                    clientSource.Dispose();
                }
                clientSource = new CancellationTokenSource();
                    
                _ = Task.Run(async () => await RunClient(client, token));
            }
            clientSource.Cancel();
            clientSource.Dispose();
        }

        private async Task RunClient(TcpClient client, CancellationToken token)
        {
            NetworkStream stream = client.GetStream();
            stream.ReadTimeout = Timeout.Infinite;
            stream.WriteTimeout = Timeout.Infinite;
            _ = Task.Run(() => _ = RunClientReadPoll(stream, token));
            while (!token.IsCancellationRequested)
            {
                Console.WriteLine("Bridge Listener: Reading client");
                string data = NetworkReadString(stream, token);
                Console.WriteLine("Bridge Listener: Read data: " + data);
                List<string> parsed = data.ParseExact(((BridgeProfile)this.Profile).WriteFormat.Replace("{GUID}", "{0}").Replace("{DATA}", "{1}")).ToList();
                if (parsed.Count == 2)
                {
                    Console.WriteLine("Parsed guid: " + parsed[0]);
                    _guids.Add(parsed[0]);
                    await this.InternalListener.Write(parsed[0], parsed[1]);
                }
            }
        }

        private async Task RunClientReadPoll(NetworkStream stream, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                Console.WriteLine("RunClientReadPoll Sleep");
                Thread.Sleep(10000);
                Console.WriteLine("RunClientReadPoll EndSleep");
                foreach(string guid in _guids)
                {
                    try
                    {
                        Console.WriteLine("reading: " + guid);
                        string data = await this.InternalListener.Read(guid);
                        Console.WriteLine("read data from internal: " + data);
                        if (!string.IsNullOrEmpty(data))
                        {
                            Console.WriteLine("Data not null or empty");
                            string formatted = "";
                            formatted = string.Format(((BridgeProfile)this.Profile).ReadFormat.Replace("{GUID}", "{0}").Replace("{DATA}", "{1}"), guid, data);
                            Console.WriteLine("formatted: " + formatted);
                            this.NetworkWriteString(stream, formatted);
                        }
                    }
                    catch (ControllerNotFoundException e)
                    {
                        this.NetworkWriteString(stream, e.Message);
                    }
                    catch (Exception)
                    {

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
            Console.WriteLine("NetworkReadString");
            byte[] size = new byte[4];
            int totalReadBytes = 0;
            do
            {
                totalReadBytes += stream.Read(size, totalReadBytes, size.Length - totalReadBytes);
                Console.WriteLine("Read1: " + totalReadBytes);
            } while (totalReadBytes < size.Length);
            int len = (size[0] << 24) + (size[1] << 16) + (size[2] << 8) + size[3];
            Console.WriteLine("Len: " + len);
            Console.WriteLine("size[0]: " + size[0]);
            Console.WriteLine("size[1]: " + size[1]);
            Console.WriteLine("size[2]: " + size[2]);
            Console.WriteLine("size[3]: " + size[3]);
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
                    Console.WriteLine("Read2: " + totalReadBytes);
                } while (totalReadBytes < len);
                Console.WriteLine("Done Reading");
                return Common.CovenantEncoding.GetString(ms.ToArray());
            }
        }
    }
}

// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Collections.Generic;

using SharpSploit.Generic;
using SharpSploit.Misc;

namespace SharpSploit.Enumeration
{
    /// <summary>
    /// Network is a library for network enumeration such as identifying live systems and open ports.
    /// </summary>
    public class Network
    {
        /// <summary>
        /// Conducts a port scan of a specified ComputerName and port and reports if the port is open.
        /// </summary>
        /// <param name="ComputerName">ComputerName to port scan.</param>
        /// <param name="Port">Port to scan.</param>
        /// <param name="Ping">Optional switch. If true, pings the ComputerName to ensure it's up before port scanning.</param>
        /// <param name="Timeout">Timeout (in milliseconds) before the port is considered down.</param>
        /// <returns>List of PortScanResults</returns>
        public static SharpSploitResultList<PortScanResult> PortScan(string ComputerName, int Port, bool Ping = true, int Timeout = 250)
        {
            return PortScan(new List<string> { ComputerName }, new List<int> { Port }, Ping, Timeout, 1);
        }

        /// <summary>
        /// Conducts a port scan of specified ComputerNames on a specified port and reports if the port is open.
        /// </summary>
        /// <param name="ComputerNames">ComputerNames to port scan.</param>
        /// <param name="Port">Port to scan.</param>
        /// <param name="Ping">Optional switch. If true, pings the ComputerNames to ensure each is up before port scanning.</param>
        /// <param name="Timeout">Timeout (in milliseconds) before a port is considered down.</param>
        /// <param name="Threads">Number of threads with which to portscan simultaneously</param>
        /// <returns>List of PortScanResults</returns>
        public static SharpSploitResultList<PortScanResult> PortScan(IList<string> ComputerNames, int Port, bool Ping = true, int Timeout = 250, int Threads = 100)
        {
            return PortScan(ComputerNames, new List<int> { Port }, Ping, Timeout, Threads);
        }

        /// <summary>
        /// Conducts a port scan of a specified ComputerName on specified ports and reports open ports.
        /// </summary>
        /// <param name="ComputerName">ComputerName to port scan.</param>
        /// <param name="Ports">Ports to scan.</param>
        /// <param name="Ping">Optional switch. If true, pings the ComputerName to ensure it's up before port scanning.</param>
        /// <param name="Timeout">Timeout (in milliseconds) before a port is considered down.</param>
        /// <param name="Threads">Number of threads with which to portscan simultaneously</param>
        /// <returns>List of PortScanResults</returns>
        public static SharpSploitResultList<PortScanResult> PortScan(string ComputerName, IList<int> Ports, bool Ping = true, int Timeout = 250, int Threads = 100)
        {
            return PortScan(new List<string> { ComputerName }, Ports, Ping, Timeout, Threads);
        }

        /// <summary>
        /// Conducts a port scan of specified ComputerNames on specified ports and reports open ports.
        /// </summary>
        /// <param name="ComputerNames">ComputerNames to port scan.</param>
        /// <param name="Ports">Ports to scan.</param>
        /// <param name="Ping">Optional switch. If true, pings the ComputerNames to ensure each is up before port scanning.</param>
        /// <param name="Timeout">Timeout (in milliseconds) before a port is considered down.</param>
        /// <param name="Threads">Number of threads with which to portscan simultaneously</param>
        /// <returns>List of PortScanResults</returns>
        public static SharpSploitResultList<PortScanResult> PortScan(IList<string> ComputerNames, IList<int> Ports, bool Ping = true, int Timeout = 250, int Threads = 100)
        {
            IList<string> scanAddresses = Utilities.ConvertCidrToIPs(ComputerNames).Distinct().ToList();
            IList<int> scanPorts = Ports.Where(P => P > 1 && P < 65536).Distinct().ToList();
            if (Ping)
            {
                SharpSploitResultList<PingResult> pingResults = Network.Ping(scanAddresses, Timeout, Threads);
                scanAddresses = pingResults.Where(PR => PR.IsUp).Select(PR => PR.ComputerName).ToList();
            }
            IList<PortScanResult> portScanResults = new List<PortScanResult>();
            using (CountdownEvent waiter = new CountdownEvent(scanAddresses.Count * Ports.Count))
            {
                object portScanResultsLock = new object();
                int runningThreads = 0;
                foreach (string ComputerName in scanAddresses)
                {
                    foreach (int Port in scanPorts)
                    {
                        TcpClient client = null;
                        if (!Utilities.IsIP(ComputerName))
                        {
                            client = new TcpClient();
                        }
                        else
                        {
                            IPAddress.TryParse(ComputerName, out IPAddress address);
                            client = new TcpClient(address.AddressFamily);
                        }
                        PortScanResult portScanResult = new PortScanResult(ComputerName, Port, true);
                        while (runningThreads >= Threads)
                        {
                            waiter.WaitOne(Timeout);
                            runningThreads--;
                        }
                        IAsyncResult asyncResult = client.BeginConnect(ComputerName, Port, new AsyncCallback((state) => {
                            try
                            {
                                client.EndConnect(state);
                                client.Close();
                            }
                            catch
                            {
                                portScanResult.IsOpen = false;
                            }
                            if (portScanResult.IsOpen)
                            {
                                lock (portScanResultsLock)
                                {
                                    portScanResults.Add(portScanResult);
                                }
                            }
                            ((CountdownEvent)state.AsyncState).Signal();
                        }), waiter);
                        runningThreads++;
                    }
                }
                waiter.Wait(Timeout * scanAddresses.Count * Ports.Count);
            }
            SharpSploitResultList<PortScanResult> results = new SharpSploitResultList<PortScanResult>();
            results.AddRange(portScanResults);

            return results;
        }

        /// <summary>
        /// Pings a specified ComputerName to identify if it is live.
        /// </summary>
        /// <param name="ComputerName">ComputerName to ping.</param>
        /// <param name="Timeout">Timeout (in milliseconds) before a ComputerName is considered down.</param>
        /// <returns></returns>
        public static SharpSploitResultList<PingResult> Ping(string ComputerName, int Timeout = 250)
        {
            return Ping(new List<string> { ComputerName }, Timeout, 1);
        }
        /// <summary>
        /// Pings specified ComputerNames to identify live systems.
        /// </summary>
        /// <param name="ComputerNames">ComputerNames to ping.</param>
        /// <param name="Timeout">Timeout (in milliseconds) before a ComputerName is considered down.</param>
        /// <param name="Threads">Number of threads with which to ping simultaneously</param>
        /// <returns></returns>
        public static SharpSploitResultList<PingResult> Ping(IList<string> ComputerNames, int Timeout = 250, int Threads = 100)
        {
            IList<string> pingAddresses = Utilities.ConvertCidrToIPs(ComputerNames).Distinct().ToList();
            SharpSploitResultList<PingResult> pingResults = new SharpSploitResultList<PingResult>();
            using (CountdownEvent waiter = new CountdownEvent(pingAddresses.Count))
            {
                object pingResultsLock = new object();
                int runningThreads = 0;
                foreach (string ComputerName in pingAddresses)
                {
                    Ping ping = new Ping();
                    PingResult pingResult = new PingResult(ComputerName, true);
                    ping.PingCompleted += new PingCompletedEventHandler((sender, e) =>
                    {
                        if (e.Reply != null && e.Reply.Status == IPStatus.Success)
                        {
                            lock (pingResultsLock)
                            {
                                pingResults.Add(pingResult);
                            }
                        }
                        ((CountdownEvent)e.UserState).Signal();
                    });
                    while (runningThreads >= Threads)
                    {
                        waiter.WaitOne();
                        runningThreads--;
                    }
                    try
                    {
                        ping.SendAsync(ComputerName, Timeout, waiter);
                        runningThreads++;
                    }
                    catch { }
                }
                waiter.Wait(Timeout * pingAddresses.Count);
            }
            return pingResults;
        }

        /// <summary>
        /// PingResult represent the result of a ping, used with the Ping() functions.
        /// </summary>
        public sealed class PingResult : SharpSploitResult
        {
            public string ComputerName { get; } = "";
            public bool IsUp { get; } = false;
            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty>
                    {
                        new SharpSploitResultProperty
                        {
                            Name = "ComputerName",
                            Value = this.ComputerName
                        },
                        new SharpSploitResultProperty
                        {
                            Name = "IsUp",
                            Value = this.IsUp
                        }
                    };
                }
            }

            public PingResult(string ComputerName = "", bool IsUp = false)
            {
                this.ComputerName = ComputerName;
                this.IsUp = IsUp;
            }
        }

        /// <summary>
        /// PortScanResult represent the result of a port scan, used with the PortScan() functions.
        /// </summary>
        public sealed class PortScanResult : SharpSploitResult
        {
            public string ComputerName { get; } = "";
            public int Port { get; } = 0;
            public bool IsOpen { get; set; } = false;
            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty>
                    {
                        new SharpSploitResultProperty
                        {
                            Name = "ComputerName",
                            Value = this.ComputerName
                        },
                        new SharpSploitResultProperty
                        {
                            Name = "Port",
                            Value = this.Port
                        },
                        new SharpSploitResultProperty
                        {
                            Name = "IsOpen",
                            Value = this.IsOpen
                        }
                    };
                }
            }

            public PortScanResult(string ComputerName = "", int Port = 0, bool IsOpen = false)
            {
                this.ComputerName = ComputerName;
                this.Port = Port;
                this.IsOpen = IsOpen;
            }
        }

        private class Utilities
        {
            private static IList<string> ConvertCidrToIPs(string CidrComputerName)
            {
                if (CidrComputerName == null || CidrComputerName == "")
                {
                    return new List<string>();
                }
                if (!IsCidr(CidrComputerName))
                {
                    return new List<string> { CidrComputerName };
                }
                // credit - https://stackoverflow.com/questions/32028166
                string[] parts = CidrComputerName.Split('.', '/');
                uint ipasnum = (Convert.ToUInt32(parts[0]) << 24) | (Convert.ToUInt32(parts[1]) << 16) |
                               (Convert.ToUInt32(parts[2]) << 8) | (Convert.ToUInt32(parts[3]));
                int maskbits = Convert.ToInt32(parts[4]);
                uint mask = 0xffffffff;
                mask <<= (32 - maskbits);
                uint ipstart = ipasnum & mask;
                uint ipend = ipasnum | ~mask;
                List<string> IPAddresses = new List<string>();
                for (uint i = ipstart; i < ipend + 1; i++)
                {
                    IPAddresses.Add(String.Format("{0}.{1}.{2}.{3}", i >> 24, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff));
                }
                return IPAddresses;
            }

            public static IList<string> ConvertCidrToIPs(IList<string> CidrComputerNames)
            {
                List<string> ComputerNames = new List<string>();
                foreach (string CidrComputerName in CidrComputerNames)
                {
                    IList<string> cns = ConvertCidrToIPs(CidrComputerName);
                    ComputerNames.AddRange(cns);
                }
                return ComputerNames;
            }

            public static bool IsCidr(string ComputerName)
            {
                string[] parts = ComputerName.Split('.', '/');
                if (parts.Length != 5)
                {
                    return false;
                }
                foreach (string part in parts)
                {
                    if (!int.TryParse(part, out int i))
                    {
                        return false;
                    }
                    if (i < 0 || i > 255)
                    {
                        return false;
                    }
                }
                if (!ComputerName.Contains("/"))
                {
                    return false;
                }
                string ippart = ComputerName.Split('/')[0];
                return ippart.Split('.').Length == 4;
            }

            public static bool IsIP(string ComputerName)
            {
                return IPAddress.TryParse(ComputerName, out IPAddress address);
            }
        }
    }
}

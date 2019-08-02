using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class Backupkey : ICommand
    {
        public static string CommandName => "backupkey";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Retrieve domain DPAPI backup key\r\n");

            string server = "";
            string outFile = "";

            if (arguments.ContainsKey("/server"))
            {
                server = arguments["/server"];
                Console.WriteLine("\r\n[*] Using server                     : {0}", server);
            }
            else
            {
                server = Interop.GetDCName();
                if (String.IsNullOrEmpty(server))
                {
                    return;
                }
                Console.WriteLine("\r\n[*] Using current domain controller  : {0}", server);
            }

            if (arguments.ContainsKey("/file"))
            {
                // if we want the backup key piped to an output file
                outFile = arguments["/file"];
            }

            Backup.GetBackupKey(server, outFile);
        }
    }
}
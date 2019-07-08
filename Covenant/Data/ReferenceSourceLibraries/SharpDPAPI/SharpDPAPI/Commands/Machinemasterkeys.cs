using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class Machinemasterkeys : ICommand
    {
        public static string CommandName => "machinemasterkeys";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Machine DPAPI Masterkey File Triage\r\n");

            Dictionary<string, string> mappings = Triage.TriageSystemMasterKeys(false);

            if (mappings.Count == 0)
            {
                Console.WriteLine("\r\n[!] No master keys decrypted!\r\n");
            }
            else
            {
                Console.WriteLine("\r\n[*] SYSTEM master key cache:\r\n");
                foreach (KeyValuePair<string, string> kvp in mappings)
                {
                    Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                }
            }
        }
    }
}
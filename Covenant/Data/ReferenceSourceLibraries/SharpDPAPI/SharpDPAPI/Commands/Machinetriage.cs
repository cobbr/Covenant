using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class Machinetriage : ICommand
    {
        public static string CommandName => "machinetriage";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Machine DPAPI Credential and Vault Triage\r\n");
            arguments.Remove("triage");

            Dictionary<string, string> mappings = Triage.TriageSystemMasterKeys();

            Triage.TriageSystemCreds(mappings);
            Triage.TriageSystemVaults(mappings);
        }
    }
}
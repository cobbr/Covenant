using System;
using System.Collections.Generic;


namespace Rubeus.Commands
{
    public class Klist : ICommand
    {
        public static string CommandName => "klist";

        public void Execute(Dictionary<string, string> arguments)
        {
            Interop.LUID luid = new Interop.LUID();

            if (arguments.ContainsKey("/luid"))
            {
                try
                {
                    luid = new Interop.LUID(arguments["/luid"]);
                }
                catch
                {
                    Console.WriteLine("[X] Invalid LUID format ({0})\r\n", arguments["/luid"]);
                    return;
                }
            }

            LSA.ListKerberosTickets(luid);
        }
    }
}
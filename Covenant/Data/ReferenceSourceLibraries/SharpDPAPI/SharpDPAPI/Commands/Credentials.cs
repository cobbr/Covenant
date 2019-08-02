using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class Credentials : ICommand
    {
        public static string CommandName => "credentials";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: User DPAPI Credential Triage\r\n");
            arguments.Remove("credentials");

            if (arguments.ContainsKey("/target"))
            {
                string target = arguments["/target"];
                arguments.Remove("/target");

                if (arguments.ContainsKey("/pvk"))
                {
                    // using a domain backup key to decrypt everything
                    string pvk64 = arguments["/pvk"];
                    byte[] backupKeyBytes;

                    if (File.Exists(pvk64))
                    {
                        backupKeyBytes = File.ReadAllBytes(pvk64);
                    }
                    else
                    {
                        backupKeyBytes = Convert.FromBase64String(pvk64);
                    }

                    // build a {GUID}:SHA1 masterkey mappings
                    Dictionary<string, string> mappings = Triage.TriageUserMasterKeys(backupKeyBytes, false);

                    if (mappings.Count == 0)
                    {
                        Console.WriteLine("\r\n[!] No master keys decrypted!\r\n");
                    }
                    else
                    {
                        Console.WriteLine("\r\n[*] User master key cache:\r\n");
                        foreach (KeyValuePair<string, string> kvp in mappings)
                        {
                            Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                        }
                    }

                    Console.WriteLine("\r\n[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!\r\n");
                    arguments = mappings;
                }

                if (File.Exists(target))
                {
                    Console.WriteLine("[*] Target Credential File: {0}\r\n", target);
                    Triage.TriageCredFile(target, arguments);
                }
                else if (Directory.Exists(target))
                {
                    Console.WriteLine("[*] Target Credential Folder: {0}\r\n", target);
                    Triage.TriageCredFolder(target, arguments);
                }
                else
                {
                    Console.WriteLine("\r\n[X] '{0}' is not a valid file or directory.", target);
                }
            }

            else if (arguments.ContainsKey("/pvk"))
            {
                // using a domain backup key to decrypt everything

                string pvk64 = arguments["/pvk"];
                string server = "";

                byte[] backupKeyBytes;

                if (File.Exists(pvk64))
                {
                    backupKeyBytes = File.ReadAllBytes(pvk64);
                }
                else
                {
                    backupKeyBytes = Convert.FromBase64String(pvk64);
                }

                Console.WriteLine("[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!");

                // build a {GUID}:SHA1 masterkey mappings
                Dictionary<string, string> mappings = new Dictionary<string, string>();

                if (arguments.ContainsKey("/server"))
                {
                    server = arguments["/server"];
                    Console.WriteLine("[*] Triaging remote server: {0}\r\n", server);
                    mappings = Triage.TriageUserMasterKeys(backupKeyBytes, false, server);
                }
                else
                {
                    Console.WriteLine("");
                    mappings = Triage.TriageUserMasterKeys(backupKeyBytes, false);
                }

                if (mappings.Count == 0)
                {
                    Console.WriteLine("[!] No master keys decrypted!\r\n");
                }
                else
                {
                    Console.WriteLine("[*] User master key cache:\r\n");
                    foreach (KeyValuePair<string, string> kvp in mappings)
                    {
                        Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                    }
                    Console.WriteLine();
                }

                Triage.TriageUserCreds(mappings, server);
            }
            else
            {
                if (arguments.ContainsKey("/server"))
                {
                    Console.WriteLine("[X] The '/server:X' argument must be used with '/pvk:BASE64...' !");
                }
                else
                {
                    Triage.TriageUserCreds(arguments);
                }
            }
        }
    }
}
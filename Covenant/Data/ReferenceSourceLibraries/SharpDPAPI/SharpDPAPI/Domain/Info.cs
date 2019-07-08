using System;

namespace SharpDPAPI.Domain
{
    public static class Info
    {
        public static void Logo()
        {
            Console.WriteLine("\r\n  __                 _   _       _ ___ ");
            Console.WriteLine(" (_  |_   _. ._ ._  | \\ |_) /\\  |_) |  ");
            Console.WriteLine(" __) | | (_| |  |_) |_/ |  /--\\ |  _|_ ");
            Console.WriteLine("                |                      ");
            Console.WriteLine("  v1.2.0                               \r\n");
        }

        public static void ShowUsage()
        {
            string usage = @"
Triage all reachable machine masterkey files (elevates to SYSTEM to retrieve the DPAPI_SYSTEM LSA secret):

  SharpDPAPI machinemasterkeys


Triage all reachable machine Credential files, Vaults, or both (elevates to SYSTEM to retrieve the DPAPI_SYSTEM LSA secret):

  SharpDPAPI <machinecredentials|machinevaults|machinetriage>


Triage all reachable user masterkey files, use a domain backup key to decrypt all that are found:

  SharpDPAPI masterkeys </pvk:BASE64... | /pvk:key.pvk>


Triage all reachable user Credential files, Vaults, or both using a domain DPAPI backup key to decrypt masterkeys:

  SharpDPAPI <credentials|vaults|triage> </pvk:BASE64... | /pvk:key.pvk>


Triage all reachable user Credential files, Vaults, or both on a *remote* system using a domain DPAPI backup key to decrypt masterkeys:

  SharpDPAPI <credentials|vaults|triage> </pvk:BASE64... | /pvk:key.pvk> /server:SERVER.domain.com


Triage all reachable user Credential files or Vaults, or both optionally using the GUID masterkey mapping to decrypt any matches:

  SharpDPAPI <credentials|vaults|triage> [GUID1:SHA1 GUID2:SHA1 ...]


Triage a specific Credential file or folder, using GUID lookups or a domain backup key for decryption:

  SharpDPAPI credentials /target:C:\FOLDER\ [GUID1:SHA1 GUID2:SHA1 ... | /pvk:BASE64... | /pvk:key.pvk]
  SharpDPAPI credentials /target:C:\FOLDER\FILE [GUID1:SHA1 GUID2:SHA1]


Triage a specific Vault folder, using GUID lookups or a domain backup key for decryption:

  SharpDPAPI vaults /target:C:\FOLDER\ [GUID1:SHA1 GUID2:SHA1 ... | /pvk:BASE64... | /pvk:key.pvk]


Retrieve a domain controller's DPAPI backup key, optionally specifying a DC and output file:

  SharpDPAPI backupkey [/server:SERVER.domain] [/file:key.pvk]
";
            Console.WriteLine(usage);
        }
    }
}

// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Covenant.Models.Covenant
{
    public class CapturedCredential
    {
        public enum CredentialType
        {
            Password,
            Hash,
            Ticket
        }

        public int Id { get; set; }
        public string Domain { get; set; }
        public string Username { get; set; }
        public string ServiceName { get; set; }
        public CredentialType Type { get; set; }

        // Adapted from https://github.com/EmpireProject/Empire
        public static List<CapturedCredential> ParseCredentials(string input)
        {
            List<string> regexes = new List<string> { "(?s)(?<=msv :).*?(?=tspkg :)", "(?s)(?<=tspkg :).*?(?=wdigest :)", "(?s)(?<=wdigest :).*?(?=kerberos :)", "(?s)(?<=kerberos :).*?(?=ssp :)", "(?s)(?<=ssp :).*?(?=credman :)", "(?s)(?<=credman :).*?(?=Authentication Id :)", "(?s)(?<=credman :).*?(?=mimikatz)" };

            string hostDomain = "";
            string domainSid = "";
            string hostName = "";

            List<string> lines = input.Split('\n').ToList();
            foreach (string line in lines.Take(2))
            {
                if (line.StartsWith("Hostname:"))
                {
                    try
                    {
                        string domain = line.Split(":")[1].Trim();
                        string temp = domain.Split("/")[0].Trim();
                        domainSid = domain.Split("/")[1].Trim();

                        hostName = temp.Split(".")[0];
                        hostDomain = String.Join(".", temp.Split(".").TakeLast(temp.Split(".").Length - 1));
                    }
                    catch (Exception) { continue; }
                }
            }
            List<CapturedCredential> credentials = new List<CapturedCredential>();
            foreach (string regex in regexes)
            {
                MatchCollection matches = Regex.Matches(input, regex);
                foreach (Match match in matches)
                {
                    List<string> lines2 = match.Groups[0].Value.Split('\n').ToList();
                    string username = "";
                    string domain = "";
                    string password = "";
                    string credType = "";

                    foreach (string line in lines2)
                    {
                        try
                        {
                            if (line.Contains("Username"))
                            {
                                username = line.Split(":")[1].Trim();
                            }
                            else if (line.Contains("Domain"))
                            {
                                domain = line.Split(":")[1].Trim();
                            }
                            else if (line.Contains("NTLM") || line.Contains("Password"))
                            {
                                password = line.Split(":")[1].Trim();
                            }
                        }
                        catch (Exception) { continue; }
                    }

                    if (username != "" && password != "" && password != "(null)")
                    {
                        string sid = "";
                        if (hostDomain.StartsWith(domain.ToLower()))
                        {
                            domain = hostDomain;
                            sid = domainSid;
                        }

                        if (IsNTLM(password))
                        {
                            credType = "hash";
                        }
                        else
                        {
                            credType = "plaintext";
                        }
                        if (!(credType == "plaintext" && username.EndsWith("$")))
                        {
                            if (IsNTLM(password))
                            {
                                credentials.Add(new CapturedHashCredential
                                {
                                    Domain = domain,
                                    Username = username,
                                    Hash = password,
                                    HashCredentialType = CapturedHashCredential.HashType.NTLM
                                });
                            }
                            else
                            {
                                credentials.Add(new CapturedPasswordCredential
                                {
                                    Domain = domain,
                                    Username = username,
                                    Password = password
                                });
                            }
                        }
                    }
                }
            }

            if (credentials.Count == 0)
            {
                for (int x = 8; x < 13; x++)
                {
                    if (lines.Count > (x-1) && lines[x].StartsWith("Domain : "))
                    {
                        string domain = "";
                        string sid = "";
                        string krbtgtHash = "";

                        try
                        {
                            string domainParts = lines[x].Split(":")[1];
                            domain = domainParts.Split("/")[0].Trim();
                            sid = domainParts.Split("/")[1].Trim();

                            if (hostDomain.StartsWith(domain.ToLower()))
                            {
                                domain = hostDomain;
                                sid = domainSid;
                            }
                            for (int y = 9; y < lines.Count; y++)
                            {
                                if (lines[y].StartsWith("User : krbtgt"))
                                {
                                    krbtgtHash = lines[y + 2].Split(":")[1].Trim();
                                    break;
                                }
                            }
                            if (krbtgtHash != "")
                            {
                                credentials.Add(new CapturedHashCredential
                                {
                                    Domain = domain,
                                    Username = "krbtgt",
                                    Hash = krbtgtHash,
                                    HashCredentialType = CapturedHashCredential.HashType.NTLM
                                });
                            }
                        }
                        catch(Exception) { continue; }
                    }
                }
            }
            if (credentials.Count == 0)
            {
                if (lines.FirstOrDefault(L => L.Contains("SAMKey")) != null)
                {
                    string lines_combined = String.Join('\n', lines);
                    string domain = lines.FirstOrDefault(L => L.Contains("Domain :")).Split(":")[1].Trim();
                    MatchCollection hash_matches = Regex.Matches(lines_combined, "(?s)RID  :.*?((?=RID  :)|$)");
                    foreach (Match match in hash_matches)
                    {
                        string user = "";
                        string userHash = "";
                        List<string> lines2 = match.Groups[0].Value.Split('\n').ToList();
                        foreach (string line in lines2)
                        {
                            try
                            {
                                if (line.Trim().StartsWith("User :"))
                                {
                                    user = line.Split(":")[1].Trim();
                                }
                                else if (line.Trim().StartsWith("Hash NTLM:"))
                                {
                                    userHash = line.Split(":")[1].Trim();
                                }
                            }
                            catch (Exception) { continue; }
                        }
                        if (domain != "" && user != "" && userHash != "")
                        {
                            credentials.Add(new CapturedHashCredential
                            {
                                Domain = domain,
                                Username = user,
                                Hash = userHash,
                                HashCredentialType = CapturedHashCredential.HashType.NTLM
                            });
                        }
                    }
                }
            }

            // Rubeus
            MatchCollection user_matches = Regex.Matches(input, "(?s)UserName                 :.*?((?=UserName                 :)|$)");
            foreach (Match match in user_matches)
            {
                List<string> lines2 = match.Groups[0].Value.Split('\n').ToList();
                string username = "";
                string domain = "";
                foreach (string line in lines2)
                {
                    if (line.Contains("UserName"))
                    {
                        username = line.Split(":")[1].Trim();
                    }
                    else if(line.Contains("Domain"))
                    {
                        domain = line.Split(":")[1].Trim();
                    }
                }
                MatchCollection ticket_matches = Regex.Matches(match.Groups[0].Value, "(?s)ServiceName              :.*?((?=ServiceName              :)|$)");
                foreach (Match ticket_match in ticket_matches)
                {

                    List<string> lines3 = ticket_match.Groups[0].Value.Split('\n').ToList();
                    string servicename = "";
                    string ticket = "";
                    string sessionkeytype = "";

                    foreach (string line in lines3)
                    {
                        try
                        {
                            if (line.Contains("ServiceName"))
                            {
                                servicename = line.Split(":")[1].Trim();
                            }
                            else if (line.Contains("SessionKeyType"))
                            {
                                sessionkeytype = line.Split(":")[1].Trim();
                            }
                            else if (line.Contains("Base64EncodedTicket"))
                            {
                                ticket = ticket_match.Groups[0].Value.Substring(ticket_match.Groups[0].Value.IndexOf("Base64EncodedTicket") + 26).Trim().Replace(" ", "").Replace("\r", "").Replace("\n","");
                            }
                        }
                        catch (Exception) { continue; }
                    }
                    if (servicename != "" && ticket != "")
                    {
                        credentials.Add(new CapturedTicketCredential
                        {
                            Domain = domain,
                            Username = username,
                            ServiceName = servicename,
                            Ticket = ticket,
                            TicketCredentialType = sessionkeytype.Contains("rc4") ?
                                                        CapturedTicketCredential.TicketType.RC4 :
                                                        CapturedTicketCredential.TicketType.AES
                        });
                    }
                }
            }
            return credentials;
        }

        private static bool IsNTLM(string input)
        {
            return Regex.IsMatch(input, "^[0-9a-f]{32}", RegexOptions.IgnoreCase);
        }
    }

    public class CapturedPasswordCredential : CapturedCredential
    {
        public string Password { get; set; }

        public CapturedPasswordCredential()
        {
            this.Type = CredentialType.Password;
        }
    }

    public class CapturedHashCredential : CapturedCredential
    {
        public enum HashType
        {
            NTLM,
            LM,
            SHA1
        }

        public string Hash { get; set; }
        public HashType HashCredentialType { get; set; }

        public CapturedHashCredential()
        {
            this.Type = CredentialType.Hash;
        }
    }

    public class CapturedTicketCredential : CapturedCredential
    {
        public enum TicketType
        {
            RC4,
            AES
        }

        public string Ticket { get; set; }
        public TicketType TicketCredentialType { get; set; }

        public CapturedTicketCredential()
        {
            this.Type = CredentialType.Ticket;
        }
    }
}

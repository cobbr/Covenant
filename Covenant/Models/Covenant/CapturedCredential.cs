// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Covenant.Models.Covenant
{
    public enum CredentialType
    {
        Password,
        Hash,
        Ticket
    }

    public class CapturedPasswordCredential : CapturedCredential
    {
        public string Password { get; set; }

        public CapturedPasswordCredential()
        {
            this.Type = CredentialType.Password;
        }
    }

    public enum HashType
    {
        NTLM,
        LM,
        SHA1
    }

    public class CapturedHashCredential : CapturedCredential
    {
        public HashType HashCredentialType { get; set; }
        public string Hash { get; set; }

        public CapturedHashCredential()
        {
            this.Type = CredentialType.Hash;
        }
    }

    public enum TicketType
    {
        RC4,
        AES
    }

    public class CapturedTicketCredential : CapturedCredential
    {
        public TicketType TicketCredentialType { get; set; }
        public string ServiceName { get; set; }
        public string Ticket { get; set; }

        public CapturedTicketCredential()
        {
            this.Type = CredentialType.Ticket;
        }
    }

    public class CapturedCredential
    {
        public int Id { get; set; }
        public CredentialType Type { get; set; }
        public string Domain { get; set; }
        public string Username { get; set; }

        // Adapted from https://github.com/EmpireProject/Empire
        public static List<CapturedCredential> ParseCredentials(string input)
        {
            List<CapturedCredential> credentials = new List<CapturedCredential>();
            // Mimikatz
            if (input.Contains("mimikatz"))
            {
                string hostDomain = "";
                string domainSid = "";
                string hostName = "";

                List<string> lines = input.Split('\n').ToList();
                foreach (string line in lines.Take(2))
                {
                    if (line.StartsWith("Hostname:", StringComparison.Ordinal))
                    {
                        try
                        {
                            string domain = string.Join(":", line.Split(":").Skip(1)).Trim();
                            string temp = domain.Split("/")[0].Trim();
                            domainSid = domain.Split("/")[1].Trim();

                            hostName = temp.Split(".")[0];
                            hostDomain = String.Join(".", temp.Split(".").TakeLast(temp.Split(".").Length - 1));
                        }
                        catch (Exception) { continue; }
                    }
                }

                // Mimikatz sekurlsa::logonpasswords
                List<string> regexes = new List<string> { "(?s)(?<=msv :).*?(?=tspkg :)", "(?s)(?<=tspkg :).*?(?=wdigest :)", "(?s)(?<=wdigest :).*?(?=kerberos :)", "(?s)(?<=kerberos :).*?(?=ssp :)", "(?s)(?<=ssp :).*?(?=credman :)", "(?s)(?<=credman :).*?(?=Authentication Id :)", "(?s)(?<=credman :).*?(?=mimikatz)" };
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
                                    username = string.Join(":", line.Split(":").Skip(1)).Trim();
                                }
                                else if (line.Contains("Domain"))
                                {
                                    domain = string.Join(":", line.Split(":").Skip(1)).Trim();
                                }
                                else if (line.Contains("NTLM") || line.Contains("Password"))
                                {
                                    password = string.Join(":", line.Split(":").Skip(1)).Trim();
                                }
                            }
                            catch (Exception) { continue; }
                        }

                        if (username != "" && password != "" && password != "(null)")
                        {
                            string sid = "";
                            if (hostDomain.StartsWith(domain.ToLower(), StringComparison.Ordinal))
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
                            if (!(credType == "plaintext" && username.EndsWith("$", StringComparison.Ordinal)))
                            {
                                if (IsNTLM(password))
                                {
                                    credentials.Add(new CapturedHashCredential
                                    {
                                        Domain = domain,
                                        Username = username,
                                        Hash = password,
                                        HashCredentialType = HashType.NTLM
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

                // Mimikatz lsadump::sam
                if (credentials.Count == 0)
                {
                    if (lines.FirstOrDefault(L => L.Contains("SAMKey")) != null)
                    {
                        string lines_combined = String.Join('\n', lines);
                        string domain_line = lines.FirstOrDefault(L => L.Contains("Domain :"));
                        string domain = string.Join(":", domain_line.Split(":").Skip(1)).Trim();
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
                                    if (line.Trim().StartsWith("User :", StringComparison.Ordinal))
                                    {
                                        user = string.Join(":", line.Split(":").Skip(1)).Trim();
                                    }
                                    else if (line.Trim().StartsWith("Hash NTLM:", StringComparison.Ordinal))
                                    {
                                        userHash = string.Join(":", line.Split(":").Skip(1)).Trim();
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
                                    HashCredentialType = HashType.NTLM
                                });
                            }
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
                        username = string.Join(":", line.Split(":").Skip(1)).Trim();
                    }
                    else if(line.Contains("Domain"))
                    {
                        domain = string.Join(":", line.Split(":").Skip(1)).Trim();
                    }
                }
                MatchCollection ticket_matches = Regex.Matches(match.Groups[0].Value, "(?s)ServiceName           :.*?((?=ServiceName              :)|$)");
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
                                servicename = string.Join(":", line.Split(":").Skip(1)).Trim();
                            }
                            else if (line.Contains("SessionKeyType"))
                            {
                                sessionkeytype = string.Join(":", line.Split(":").Skip(1)).Trim();
                            }
                            else if (line.Contains("Base64EncodedTicket"))
                            {
                                ticket = ticket_match.Groups[0].Value.Substring(ticket_match.Groups[0].Value.IndexOf("Base64EncodedTicket", StringComparison.Ordinal) + 26).Trim().Replace(" ", "").Replace("\r", "").Replace("\n","");
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
                            TicketCredentialType = sessionkeytype.Contains("rc4") ? TicketType.RC4 : TicketType.AES
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
}

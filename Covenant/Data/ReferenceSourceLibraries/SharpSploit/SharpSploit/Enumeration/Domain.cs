// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.DirectoryServices;
using System.IdentityModel.Tokens;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Runtime.InteropServices;

using System.Text.RegularExpressions;
using System.Collections.Generic;

using SharpSploit.Execution;

namespace SharpSploit.Enumeration
{
    /// <summary>
    /// Domain is a library for domain enumeration that can be used to search for and query for information from
    /// DomainObjects such as users, groups, and computers.
    /// </summary>
    /// <remarks>
    /// Domain is adapted from Will Schroeder's (@harmj0y) PowerView (Found
    /// at https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)
    /// </remarks>
    public class Domain
    {
        /// <summary>
        /// DomainSearcher is a LDAP searcher class for domain enumeration.
        /// </summary>
        /// <remarks>
        /// DomainSearcher is adapted from Will Schroeder's (@harmj0y) PowerView. (Found
        /// at https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)
        /// </remarks>
        public class DomainSearcher
        {
            public Credential Credentials { get; set; } = null;
            private string Domain { get; set; }
            private string Server { get; set; }
            private DirectorySearcher DirectorySearcher { get; set; }

            /// <summary>
            /// Constructor for the DomainSearcher class.
            /// </summary>
            /// <param name="Credentials">Optional alternative Credentials to authenticate to the Domain.</param>
            /// <param name="Domain">Optional alternative Domain to authenticate to and search.</param>
            /// <param name="Server">Optional alternative Server within the Domain to authenticate to and search.</param>
            /// <param name="SearchBase">Optional SearchBase to prepend to all LDAP searches.</param>
            /// <param name="SearchString">Optional SearchString to append to SearchBase for all LDAP searches.</param>
            /// <param name="SearchScope">Optional SearchScope for the underlying DirectorySearcher object.</param>
            /// <param name="ResultPageSize">Optional ResultPageSize for the underlying DirectorySearcher object.</param>
            /// <param name="ServerTimeLimit">Optional max time limit for the server per search.</param>
            /// <param name="TombStone">Optionally retrieve deleted/tombstoned DomainObjects</param>
            /// <param name="SecurityMasks">Optional SecurityMasks for the underlying DirectorySearcher object.</param>
            public DomainSearcher(Credential Credentials = null, string Domain = "", string Server = "", string SearchBase = "", string SearchString = "", SearchScope SearchScope = SearchScope.Subtree,
                int ResultPageSize = 200, TimeSpan ServerTimeLimit = default(TimeSpan), bool TombStone = false, SecurityMasks SecurityMasks = SecurityMasks.None)
            {
                this.Credentials = Credentials;
                if (this.Credentials == null)
                {
                    this.Credentials = Credential.EmptyCredential;
                }
                this.Domain = Domain;
                if (this.Domain == "")
                {
                    this.Domain = Environment.UserDomainName;
                }
                this.Server = Server;
                if (this.Server == "")
                {
                    string logonserver = Environment.GetEnvironmentVariable("logonserver");
                    this.Server = logonserver.Replace("\\", "") + this.Domain;
                }
                if (SearchBase == "")
                {
                    SearchBase = "LDAP://" + this.GetBaseDN();
                }
                DirectorySearcher searcher = null;
                if (this.Credentials != null && this.Credentials != Credential.EmptyCredential)
                {
                    DirectoryEntry searchRoot = new DirectoryEntry(SearchBase + SearchString, Credentials.UserName, Credentials.Password);
                    searcher = new DirectorySearcher(searchRoot);
                }
                else
                {
                    searcher = new DirectorySearcher(SearchBase + SearchString);
                }

                searcher.SearchScope = SearchScope;
                searcher.PageSize = ResultPageSize;
                searcher.CacheResults = false;
                searcher.ReferralChasing = ReferralChasingOption.All;
                if (ServerTimeLimit != default(TimeSpan))
                {
                    searcher.ServerTimeLimit = ServerTimeLimit;
                }
                searcher.Tombstone = TombStone;
                searcher.SecurityMasks = SecurityMasks;
                this.DirectorySearcher = searcher;
            }

            /// <summary>
            /// Gets a specified user `DomainObject` in the current Domain.
            /// </summary>
            /// <param name="Identity">Username to search for.</param>
            /// <param name="LDAPFilter">Optional LDAP filter to apply to the search.</param>
            /// <param name="Properties">Optional list of properties to retrieve from the DomainObject.
            /// If not specified, all properties are included.</param>
            /// <param name="UACFilter">Optional filter to parse the userAccountControl DomainObject property.</param>
            /// <param name="SPN">Optionally filter for only a DomainObject with an SPN set.</param>
            /// <param name="AllowDelegation">Optionally filter for only a DomainObject that allows for delegation.</param>
            /// <param name="DisallowDelegation">Optionally filter for only a DomainObject that does not allow for delegation.</param>
            /// <param name="AdminCount">Optionally filter for only a DomainObject with the AdminCount property set.</param>
            /// <param name="TrustedToAuth">Optionally filter for only a DomainObject that is trusted to authenticate for other DomainObjects</param>
            /// <param name="PreauthNotRequired">Optionally filter for only a DomainObject does not require Kerberos preauthentication.</param>
            /// <returns>Matching user DomainObject</returns>
            public DomainObject GetDomainUser(string Identity, string LDAPFilter = "", IEnumerable<string> Properties = null, IEnumerable<UACEnum> UACFilter = null, bool SPN = false, bool AllowDelegation = false, bool DisallowDelegation = false, bool AdminCount = false, bool TrustedToAuth = false, bool PreauthNotRequired = false)
            {
                return this.GetDomainUsers(new List<string> { Identity }, LDAPFilter, Properties, UACFilter, SPN, AllowDelegation, DisallowDelegation, AdminCount, TrustedToAuth, PreauthNotRequired, true).FirstOrDefault();
            }

            /// <summary>
            /// Gets a list of specified (or all) user `DomainObject`s in the current Domain.
            /// </summary>
            /// <param name="Identities">Optional list of usernames to search for.</param>
            /// <param name="LDAPFilter">Optional LDAP filter to apply to the search.</param>
            /// <param name="Properties">Optional list of properties to retrieve from the DomainObject.
            /// If not specified, all properties are included.</param>
            /// <param name="UACFilter">Optional filter to parse the userAccountControl DomainObject property.</param>
            /// <param name="SPN">Optionally filter for only a DomainObject with an SPN set.</param>
            /// <param name="AllowDelegation">Optionally filter for only a DomainObject that allows for delegation.</param>
            /// <param name="DisallowDelegation">Optionally filter for only a DomainObject that does not allow for delegation.</param>
            /// <param name="AdminCount">Optionally filter for only a DomainObject with the AdminCount property set.</param>
            /// <param name="TrustedToAuth">Optionally filter for only a DomainObject that is trusted to authenticate for other DomainObjects</param>
            /// <param name="PreauthNotRequired">Optionally filter for only a DomainObject does not require Kerberos preauthentication.</param>
            /// <param name="FindOne">Optionally find only the first matching DomainObject.</param>
            /// <returns>List of matching user DomainObjects</returns>
            public List<DomainObject> GetDomainUsers(IEnumerable<string> Identities = null, string LDAPFilter = "", IEnumerable<string> Properties = null, IEnumerable<UACEnum> UACFilter = null, bool SPN = false, bool AllowDelegation = false, bool DisallowDelegation = false, bool AdminCount = false, bool TrustedToAuth = false, bool PreauthNotRequired = false, bool FindOne = false)
            {
                string Filter = "";
                string IdentityFilter = ConvertIdentitiesToFilter(Identities);
                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += "(|" + IdentityFilter + ")";
                }
                if (SPN)
                {
                    Filter += "(servicePrincipalName=*)";
                }
                if (AllowDelegation)
                {
                    Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))";
                }
                if (DisallowDelegation)
                {
                    Filter += "(userAccountControl:1.2.840.113556.1.4.803:=1048574)";
                }
                if (AdminCount)
                {
                    Filter += "(admincount=1)";
                }
                if (TrustedToAuth)
                {
                    Filter += "(msds-allowedtodelegateto=*)";
                }
                if (PreauthNotRequired)
                {
                    Filter += "(userAccountControl:1.2.840.113556.1.4.803:=4194304)";
                }
                if (UACFilter != null)
                {
                    foreach (UACEnum uac in UACFilter)
                    {
                        Filter += "(userAccountControl:1.2.840.113556.1.4.803:=" + ((int)uac) + ")";
                    }
                }

                Filter += LDAPFilter;
                this.DirectorySearcher.Filter = "(&(samAccountType=805306368)" + Filter + ")";

                if (Properties != null)
                {
                    this.DirectorySearcher.PropertiesToLoad.Clear();
                    this.DirectorySearcher.PropertiesToLoad.AddRange(Properties.ToArray());
                }
                List<SearchResult> results = new List<SearchResult>();
                try
                {
                    if (FindOne)
                    {
                        results.Add(this.DirectorySearcher.FindOne());
                    }
                    else
                    {
                        var collection = this.DirectorySearcher.FindAll();
                        foreach (SearchResult result in collection)
                        {
                            results.Add(result);
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Exception: Can't construct Domain Searcher: " + e.Message + e.StackTrace);
                }
                return ConvertSearchResultsToDomainObjects(results);
            }

            /// <summary>
            /// Gets a specified group `DomainObject` in the current Domain.
            /// </summary>
            /// <param name="Identity">Group name to search for.</param>
            /// <param name="LDAPFilter">Optional LDAP filter to apply to the search.</param>
            /// <param name="Properties">Optional list of properties to retrieve from the DomainObject.
            /// If not specified, all properties are included.</param>
            /// <param name="AdminCount">Optionally filter for only a DomainObject with the AdminCount property set.</param>
            /// <param name="GroupScope">Optionally filter for a GroupScope (DomainLocal, Global, Universal, etc).</param>
            /// <param name="GroupProperty">Optionally filter for a GroupProperty (Security, Distribution, CreatedBySystem,
            /// NotCreatedBySystem,etc)</param>
            /// <returns>Matching group DomainObject</returns>
            public DomainObject GetDomainGroup(string Identity, string LDAPFilter = "", IEnumerable<string> Properties = null, bool AdminCount = false, string GroupScope = "", string GroupProperty = "")
            {
                return this.GetDomainGroups(new List<string> { Identity }, LDAPFilter, Properties, AdminCount, GroupScope, GroupProperty, true).FirstOrDefault();
            }

            /// <summary>
            /// Gets a list of specified (or all) group `DomainObject`s in the current Domain.
            /// </summary>
            /// <param name="Identities">Optional list of group names to search for.</param>
            /// <param name="LDAPFilter">Optional LDAP filter to apply to the search.</param>
            /// <param name="Properties">Optional list of properties to retrieve from the DomainObject.
            /// If not specified, all properties are included.</param>
            /// <param name="AdminCount">Optionally filter for only a DomainObject with the AdminCount property set.</param>
            /// <param name="GroupScope">Optionally filter for a GroupScope (DomainLocal, Global, Universal, etc).</param>
            /// <param name="GroupProperty">Optionally filter for a GroupProperty (Security, Distribution, CreatedBySystem,
            /// NotCreatedBySystem,etc).</param>
            /// <param name="FindOne">Optionally find only the first matching DomainObject.</param>
            /// <returns>List of matching group DomainObjects</returns>
            public List<DomainObject> GetDomainGroups(IEnumerable<string> Identities = null, string LDAPFilter = "", IEnumerable<string> Properties = null, bool AdminCount = false, string GroupScope = "", string GroupProperty = "", bool FindOne = false)
            {
                string Filter = "";
                string IdentityFilter = ConvertIdentitiesToFilter(Identities);
                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += "(|" + IdentityFilter + ")";
                }
                if (AdminCount)
                {
                    Filter += "(admincount=1)";
                }
                if (GroupScope == "DomainLocal")
                {
                    Filter += "(groupType:1.2.840.113556.1.4.803:=4)";
                }
                else if (GroupScope == "NotDomainLocal")
                {
                    Filter += "(!(groupType:1.2.840.113556.1.4.803:=4))";
                }
                else if (GroupScope == "Global")
                {
                    Filter += "(groupType:1.2.840.113556.1.4.803:=2)";
                }
                else if (GroupScope == "NotGlobal")
                {
                    Filter += "(!(groupType:1.2.840.113556.1.4.803:=2))";
                }
                else if (GroupScope == "Universal")
                {
                    Filter += "(groupType:1.2.840.113556.1.4.803:=8)";
                }
                else if (GroupScope == "NotUniversal")
                {
                    Filter += "(!(groupType:1.2.840.113556.1.4.803:=8))";
                }

                if (GroupProperty == "Security")
                {
                    Filter += "(groupType:1.2.840.113556.1.4.803:=2147483648)";
                }
                else if (GroupProperty == "Distribution")
                {
                    Filter += "(!(groupType:1.2.840.113556.1.4.803:=2147483648))";
                }
                else if (GroupProperty == "CreatedBySystem")
                {
                    Filter += "(groupType:1.2.840.113556.1.4.803:=1)";
                }
                else if (GroupProperty == "NotCreatedBySystem")
                {
                    Filter += "(!(groupType:1.2.840.113556.1.4.803:=1))";
                }

                Filter += LDAPFilter;
                this.DirectorySearcher.Filter = "(&(objectCategory=group)" + Filter + ")";

                if (Properties != null)
                {
                    this.DirectorySearcher.PropertiesToLoad.Clear();
                    this.DirectorySearcher.PropertiesToLoad.AddRange(Properties.ToArray());
                }
                List<SearchResult> results = new List<SearchResult>();
                try
                {
                    if (FindOne)
                    {
                        results.Add(this.DirectorySearcher.FindOne());
                    }
                    else
                    {
                        var collection = this.DirectorySearcher.FindAll();
                        foreach (SearchResult result in collection)
                        {
                            results.Add(result);
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Exception: Can't construct Domain Searcher: " + e.Message + e.StackTrace);
                }
                return ConvertSearchResultsToDomainObjects(results);
            }

            /// <summary>
            /// Gets a specified computer `DomainObject` in the current Domain.
            /// </summary>
            /// <param name="Identity">ComputerName to search for</param>
            /// <param name="LDAPFilter">Optional LDAP filter to apply to the search.</param>
            /// <param name="Properties">Optional list of properties to retrieve from the DomainObject.
            /// If not specified, all properties are included.</param>
            /// <param name="UACFilter">Optional filter to parse the userAccountControl DomainObject property.</param>
            /// <param name="Unconstrained">Optionally filter for only a DomainObject that has unconstrained delegation.</param>
            /// <param name="TrustedToAuth">Optionally filter for only a DomainObject that is trusted to authenticate for other DomainObjects</param>
            /// <param name="Printers">Optionally return only a DomainObject that is a printer.</param>
            /// <param name="SPN">Optionally filter for only a DomainObject with an SPN set.</param>
            /// <param name="OperatingSystem">Optionally filter for only a DomainObject with a specific Operating System, wildcards accepted.</param>
            /// <param name="ServicePack">Optionally filter for only a DomainObject with a specific service pack, wildcards accepted.</param>
            /// <param name="SiteName">Optionally filter for only a DomainObject in a specific Domain SiteName, wildcards accepted.</param>
            /// <param name="Ping">Optional switch, ping the computer to ensure it's up before enumerating.</param>
            /// <returns>Matching computer DomainObject</returns>
            public DomainObject GetDomainComputer(string Identity, string LDAPFilter = "", IEnumerable<string> Properties = null, IEnumerable<UACEnum> UACFilter = null, bool Unconstrained = false, bool TrustedToAuth = false, bool Printers = false, string SPN = "", string OperatingSystem = "", string ServicePack = "", string SiteName = "", bool Ping = false)
            {
                return this.GetDomainComputers(new List<string> { Identity }, LDAPFilter, Properties, UACFilter, Unconstrained, TrustedToAuth, Printers, SPN, OperatingSystem, ServicePack, SiteName, Ping, true).FirstOrDefault();
            }

            /// <summary>
            ///  Gets a list of specified (or all) computer `DomainObject`s in the current Domain.
            /// </summary>
            /// <param name="Identities">Optional list of ComputerNames to search for.</param>
            /// <param name="LDAPFilter">Optional LDAP filter to apply to the search.</param>
            /// <param name="Properties">Optional list of properties to retrieve from the DomainObject.
            /// If not specified, all properties are included.</param>
            /// <param name="UACFilter">Optional filter to parse the userAccountControl DomainObject property.</param>
            /// <param name="Unconstrained">Optionally filter for only a DomainObject that has unconstrained delegation.</param>
            /// <param name="TrustedToAuth">Optionally filter for only a DomainObject that is trusted to authenticate for other DomainObjects</param>
            /// <param name="Printers">Optionally return only a DomainObject that is a printer.</param>
            /// <param name="SPN">Optionally filter for only a DomainObject with an SPN set.</param>
            /// <param name="OperatingSystem">Optionally filter for only a DomainObject with a specific Operating System, wildcards accepted.</param>
            /// <param name="ServicePack">Optionally filter for only a DomainObject with a specific service pack, wildcards accepted.</param>
            /// <param name="SiteName">Optionally filter for only a DomainObject in a specific Domain SiteName, wildcards accepted.</param>
            /// <param name="Ping">Optional switch, ping the computer to ensure it's up before enumerating.</param>
            /// <param name="FindOne">Optionally find only the first matching DomainObject.</param>
            /// <returns>List of matching computer DomainObjects</returns>
            public List<DomainObject> GetDomainComputers(IEnumerable<string> Identities = null, string LDAPFilter = "", IEnumerable<string> Properties = null, IEnumerable<UACEnum> UACFilter = null, bool Unconstrained = false, bool TrustedToAuth = false, bool Printers = false, string SPN = "", string OperatingSystem = "", string ServicePack = "", string SiteName = "", bool Ping = false, bool FindOne = false)
            {
                string Filter = "";
                string IdentityFilter = ConvertIdentitiesToFilter(Identities, DomainObjectType.Computer);
                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += "(|" + IdentityFilter + ")";
                }

                if (Unconstrained)
                {
                    Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)";
                }
                if (TrustedToAuth)
                {
                    Filter += "(msds-allowedtodelegateto=*)";
                }
                if (Printers)
                {
                    Filter += "(objectCategory=printQueue)";
                }
                if (SPN != "")
                {
                    Filter += "(servicePrincipalName=" + SPN + ")";
                }
                if (OperatingSystem != "")
                {
                    Filter += "(operatingsystem=" + OperatingSystem + ")";
                }
                if (ServicePack != "")
                {
                    Filter += "(operatingsystemservicepack=" + ServicePack + ")";
                }
                if (SiteName != "")
                {
                    Filter += "(serverreferencebl=" + SiteName + ")";
                }

                Filter += LDAPFilter;
                if (UACFilter != null)
                {
                    foreach (UACEnum uac in UACFilter)
                    {
                        Filter += "(userAccountControl:1.2.840.113556.1.4.803:=" + ((int)uac) + ")";
                    }
                }

                this.DirectorySearcher.Filter = "(&(samAccountType=805306369)" + Filter + ")";

                List<SearchResult> results = new List<SearchResult>();
                try
                {
                    if (FindOne)
                    {
                        results.Add(this.DirectorySearcher.FindOne());
                    }
                    else
                    {
                        var collection = this.DirectorySearcher.FindAll();
                        foreach (SearchResult result in collection)
                        {
                            results.Add(result);
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Exception: Can't construct Domain Searcher: " + e.Message + e.StackTrace);
                }
                return ConvertSearchResultsToDomainObjects(results);
            }

            /// <summary>
            /// Gets `SPNTicket`s for specified `DomainObject`s.
            /// </summary>
            /// <param name="DomainObjects">List of DomainObjects with an SPN set.</param>
            /// <returns>List of SPNTickets for the specified DomainObjects</returns>
            public static List<SPNTicket> GetDomainSPNTickets(IEnumerable<DomainObject> DomainObjects)
            {
                List<SPNTicket> tickets = new List<SPNTicket>();
                foreach (DomainObject ldap in DomainObjects)
                {
                    tickets.Add(GetDomainSPNTicket(ldap));
                }
                return tickets;
            }

            /// <summary>
            /// Get `SPNTicket` for specified `DomainObject`.
            /// </summary>
            /// <param name="DomainObject">DomainObject with an SPN set.</param>
            /// <returns>SPNTicker for the specified DomainObject</returns>
            public static SPNTicket GetDomainSPNTicket(DomainObject DomainObject)
            {
                var ticket = new KerberosRequestorSecurityToken(DomainObject.serviceprincipalname);
                if (ticket == null) { return null; }
                var ticketByteStream = ticket.GetRequest();
                if (ticketByteStream == null) { return null; }
                var tickethexstream = BitConverter.ToString(ticketByteStream).Replace("-", "");

                return new SPNTicket(DomainObject.serviceprincipalname, DomainObject.samaccountname, Environment.UserDomainName, tickethexstream);
            }

            /// <summary>
            /// Gets a list of `SPNTicket`s for specified (or all) users with a SPN set in the current Domain.
            /// </summary>
            /// <param name="Identities">Username to Kerberoast of a user with an SPN set.</param>
            /// <param name="LDAPFilter">Optional LDAP filter when searching for users with an SPN set.</param>
            /// <param name="UACFilter">Optional filter to parse the userAccountControl DomainObject property.</param>
            /// <param name="FindOne">If true, will only find a single SPNTicket for the first user found with an SPN set.</param>
            /// <returns>List of SPNTickets</returns>
            public List<SPNTicket> Kerberoast(IEnumerable<string> Identities = null, string LDAPFilter = "", IEnumerable<UACEnum> UACFilter = null, bool FindOne = false)
            {
                return GetDomainSPNTickets(this.GetDomainUsers(Identities, LDAPFilter, null, null, true, false, false, false, false, false, FindOne).Where(U => U.samaccountname != "krbtgt").ToList());
            }

            /// <summary>
            /// Gets a list of `SPNTicket`s for specified (or all) users with a SPN set in the current Domain.
            /// </summary>
            /// <param name="Identity">Optional list of users to Kerberoast. If null, all users with an SPN set will be used.</param>
            /// <param name="LDAPFilter">Optional LDAP filter when searching for users with an SPN set.</param>
            /// <param name="UACFilter">Optional filter to parse the userAccountControl DomainObject property.</param>
            /// <returns>List of SPNTickets</returns>
            public SPNTicket Kerberoast(string Identity, string LDAPFilter = "", IEnumerable<UACEnum> UACFilter = null)
            {
                return GetDomainSPNTicket(this.GetDomainUser(Identity, LDAPFilter, null, null, true, false, false, false, false, false));
            }

            private string GetBaseDN()
            {
                return "DC=" + this.Domain.Replace(".", ",DC=");
            }

            private static List<DomainObject> ConvertSearchResultsToDomainObjects(IEnumerable<SearchResult> Results)
            {
                List<DomainObject> ldaps = new List<DomainObject>();
                foreach (SearchResult result in Results)
                {
                    ldaps.Add(ConvertLDAPProperty(result));
                }
                return ldaps;
            }

            private static DomainObject ConvertLDAPProperty(SearchResult Result)
            {
                DomainObject ldap = new DomainObject();
                foreach (string PropertyName in Result.Properties.PropertyNames)
                {
                    if (Result.Properties[PropertyName].Count == 0) { continue; }
                    if (PropertyName == "objectsid")
                    {
                        ldap.objectsid = new SecurityIdentifier((byte[])Result.Properties["objectsid"][0], 0).Value;
                    }
                    else if (PropertyName == "sidhistory")
                    {
                        List<string> historyListTemp = new List<string>();
                        foreach (byte[] bytes in Result.Properties["sidhistory"])
                        {
                            historyListTemp.Add(new SecurityIdentifier(bytes, 0).Value);
                        }
                        ldap.sidhistory = historyListTemp.ToArray();
                    }
                    else if (PropertyName == "grouptype")
                    {
                        try { ldap.grouptype = (GroupTypeEnum)Enum.Parse(typeof(GroupTypeEnum), Result.Properties["grouptype"][0].ToString()); }
                        catch (Exception) { }
                    }
                    else if (PropertyName == "samaccounttype")
                    {
                        try { ldap.samaccounttype = (SamAccountTypeEnum)Enum.Parse(typeof(SamAccountTypeEnum), Result.Properties["samaccounttype"][0].ToString()); }
                        catch (Exception) { }
                    }
                    else if (PropertyName == "objectguid")
                    {
                        ldap.objectguid = new Guid((byte[])Result.Properties["objectguid"][0]).ToString();
                    }
                    else if (PropertyName == "useraccountcontrol")
                    {
                        try { ldap.useraccountcontrol = (UACEnum)Enum.Parse(typeof(UACEnum), Result.Properties["useraccountcontrol"][0].ToString()); }
                        catch (Exception) { }
                    }
                    else if (PropertyName == "ntsecuritydescriptor")
                    {
                        var desc = new RawSecurityDescriptor((byte[])Result.Properties["ntsecuritydescriptor"][0], 0);
                        ldap.Owner = desc.Owner;
                        ldap.Group = desc.Group;
                        ldap.DiscretionaryAcl = desc.DiscretionaryAcl;
                        ldap.SystemAcl = desc.SystemAcl;
                    }
                    else if (PropertyName == "accountexpires")
                    {
                        if ((long)Result.Properties["accountexpires"][0] >= DateTime.MaxValue.Ticks)
                        {
                            ldap.accountexpires = DateTime.MaxValue;
                        }
                        try
                        {
                            ldap.accountexpires = DateTime.FromFileTime((long)Result.Properties["accountexpires"][0]);
                        }
                        catch (ArgumentOutOfRangeException)
                        {
                            ldap.accountexpires = DateTime.MaxValue;
                        }
                    }
                    else if (PropertyName == "lastlogon" || PropertyName == "lastlogontimestamp" || PropertyName == "pwdlastset" ||
                             PropertyName == "lastlogoff" || PropertyName == "badPasswordTime")
                    {
                        DateTime dateTime = DateTime.MinValue;
                        if (Result.Properties[PropertyName][0].GetType().Name == "System.MarshalByRefObject")
                        {
                            var comobj = (MarshalByRefObject)Result.Properties[PropertyName][0];
                            int high = (int)comobj.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                            int low = (int)comobj.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                            dateTime = DateTime.FromFileTime(int.Parse("0x" + high + "" + low, System.Globalization.NumberStyles.HexNumber));
                        }
                        else
                        {
                            dateTime = DateTime.FromFileTime((long)Result.Properties[PropertyName][0]);
                        }
                        if (PropertyName == "lastlogon") { ldap.lastlogon = dateTime; }
                        else if (PropertyName == "lastlogontimestamp") { ldap.lastlogontimestamp = dateTime; }
                        else if (PropertyName == "pwdlastset") { ldap.pwdlastset = dateTime; }
                        else if (PropertyName == "lastlogoff") { ldap.lastlogoff = dateTime; }
                        else if (PropertyName == "badPasswordTime") { ldap.badpasswordtime = dateTime; }
                    }
                    else
                    {
                        string property = "0";
                        if (Result.Properties[PropertyName][0].GetType().Name == "System.MarshalByRefObject")
                        {
                            var comobj = (MarshalByRefObject)Result.Properties[PropertyName][0];
                            int high = (int)comobj.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                            int low = (int)comobj.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                            property = int.Parse("0x" + high + "" + low, System.Globalization.NumberStyles.HexNumber).ToString();
                        }
                        else if (Result.Properties[PropertyName].Count == 1)
                        {
                            property = Result.Properties[PropertyName][0].ToString();
                        }
                        else
                        {
                            List<string> propertyList = new List<string>();
                            foreach (object prop in Result.Properties[PropertyName])
                            {
                                propertyList.Add(prop.ToString());
                            }
                            property = String.Join(", ", propertyList.ToArray());
                        }
                        if (PropertyName == "samaccountname") { ldap.samaccountname = property; }
                        else if (PropertyName == "distinguishedname") { ldap.distinguishedname = property; }
                        else if (PropertyName == "cn") { ldap.cn = property; }
                        else if (PropertyName == "admincount") { ldap.admincount = property; }
                        else if (PropertyName == "serviceprincipalname") { ldap.serviceprincipalname = property; }
                        else if (PropertyName == "name") { ldap.name = property; }
                        else if (PropertyName == "description") { ldap.description = property; }
                        else if (PropertyName == "memberof") { ldap.memberof = property; }
                        else if (PropertyName == "logoncount") { ldap.logoncount = property; }
                        else if (PropertyName == "badpwdcount") { ldap.badpwdcount = property; }
                        else if (PropertyName == "whencreated") { ldap.whencreated = property; }
                        else if (PropertyName == "whenchanged") { ldap.whenchanged = property; }
                        else if (PropertyName == "codepage") { ldap.codepage = property; }
                        else if (PropertyName == "objectcategory") { ldap.objectcategory = property; }
                        else if (PropertyName == "usnchanged") { ldap.usnchanged = property; }
                        else if (PropertyName == "instancetype") { ldap.instancetype = property; }
                        else if (PropertyName == "objectclass") { ldap.objectclass = property; }
                        else if (PropertyName == "iscriticalsystemobject") { ldap.iscriticalsystemobject = property; }
                        else if (PropertyName == "usncreated") { ldap.usncreated = property; }
                        else if (PropertyName == "dscorepropagationdata") { ldap.dscorepropagationdata = property; }
                        else if (PropertyName == "adspath") { ldap.adspath = property; }
                        else if (PropertyName == "countrycode") { ldap.countrycode = property; }
                        else if (PropertyName == "primarygroupid") { ldap.primarygroupid = property; }
                        else if (PropertyName == "msds_supportedencryptiontypes") { ldap.msds_supportedencryptiontypes = property; }
                        else if (PropertyName == "showinadvancedviewonly") { ldap.showinadvancedviewonly = property; }
                    }
                }
                return ldap;
            }

            private static string ConvertIdentitiesToFilter(IEnumerable<string> Identities, DomainObjectType ObjectType = DomainObjectType.User)
            {
                if (Identities == null) { return ""; }
                string IdentityFilter = "";
                foreach (string Identity in Identities)
                {
                    if (Identity == null || Identity == "") { continue; }
                    string IdentityInstance = Identity.Replace("(", "\\28").Replace(")", "\\29");
                    if (Regex.IsMatch(IdentityInstance, "^S-1-"))
                    {
                        IdentityFilter += "(objectsid=" + IdentityInstance + ")";
                    }
                    else if (Regex.IsMatch(IdentityInstance, "^CN="))
                    {
                        IdentityFilter += "(distinguishedname=" + IdentityInstance + ")";
                    }
                    else if (ObjectType == DomainObjectType.Computer && IdentityInstance.Contains("."))
                    {
                        IdentityFilter += "(|(name=" + IdentityInstance + ")(dnshostname=" + IdentityInstance + "))";
                    }
                    else if (Regex.IsMatch(IdentityInstance, "^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$"))
                    {
                        byte[] bytes = new Guid(IdentityInstance).ToByteArray();
                        string GuidByteString = "";
                        foreach (Byte b in bytes)
                        {
                            GuidByteString += "\\" + b.ToString("X2");
                        }
                        IdentityFilter += "(objectguid=" + GuidByteString + ")";
                    }
                    else if (ObjectType == DomainObjectType.User || ObjectType == DomainObjectType.Group)
                    {
                        if (IdentityInstance.Contains("\\"))
                        {
                            string ConvertedIdentityInstance = ConvertADName(IdentityInstance.Replace("\\28", "(").Replace("\\29", ")"));
                            if (ConvertedIdentityInstance != null && ConvertedIdentityInstance != "")
                            {
                                string UserDomain = ConvertedIdentityInstance.Substring(0, ConvertedIdentityInstance.IndexOf("/"));
                                string UserName = ConvertedIdentityInstance.Substring(0, ConvertedIdentityInstance.IndexOf("/"));
                                IdentityFilter += "(samAccountName=" + UserName + ")";
                            }
                        }
                        else if (ObjectType == DomainObjectType.User)
                        {
                            IdentityFilter += "(samAccountName=" + IdentityInstance + ")";
                        }
                        else if (ObjectType == DomainObjectType.Group)
                        {
                            IdentityFilter += "(|(samAccountName=" + IdentityInstance + ")(name=" + IdentityInstance + "))";
                        }
                    }
                    else if (ObjectType == DomainObjectType.Computer)
                    {
                        IdentityFilter += "(name=" + IdentityInstance + ")";
                    }
                }
                return IdentityFilter;
            }

            private static string ConvertADName(string Identity, NameType type = NameType.Canonical)
            {
                Win32.ActiveDs.Init(3, null);
                Win32.ActiveDs.put_ChaseReferral(0x60);
                Win32.ActiveDs.Set(8, Identity);
                string adname = "";
                Win32.ActiveDs.Get((int)type, ref adname);
                return adname;
            }
        }

        /// <summary>
        /// Credential to authenticate to the Domain with a DomainSearcher object.
        /// </summary>
        public class Credential
        {
            public string UserName { get; set; }
            public string Password { get; set; }
            public Credential(string UserName, string Password)
            {
                this.UserName = UserName;
                this.Password = Password;
            }

            public static Credential EmptyCredential = new Credential("", "");
        }

        public enum DomainObjectType
        {
            User,
            Group,
            Computer
        }

        /// <summary>
        /// Generic DomainObject class for LDAP entries in Active Directory.
        /// </summary>
        public class DomainObject
        {
            public string samaccountname { get; set; }
            public SamAccountTypeEnum samaccounttype { get; set; }
            public string distinguishedname { get; set; }
            public string cn { get; set; }
            public string objectsid { get; set; }
            public string[] sidhistory { get; set; }
            public GroupTypeEnum grouptype { get; set; }
            public SecurityIdentifier Owner { get; set; }
            public SecurityIdentifier Group { get; set; }
            public RawAcl DiscretionaryAcl { get; set; }
            public RawAcl SystemAcl { get; set; }

            public string admincount { get; set; }
            public string serviceprincipalname { get; set; }
            public string name { get; set; }
            public string description { get; set; }
            public string memberof { get; set; }
            public string logoncount { get; set; }
            public UACEnum useraccountcontrol { get; set; }

            public string badpwdcount { get; set; }
            public DateTime badpasswordtime { get; set; }
            public DateTime pwdlastset { get; set; }
            public string whencreated { get; set; }
            public string whenchanged { get; set; }
            public DateTime accountexpires { get; set; }

            public DateTime lastlogon { get; set; }
            public DateTime lastlogoff { get; set; }

            public string codepage { get; set; }
            public string objectcategory { get; set; }
            public string usnchanged { get; set; }
            public string instancetype { get; set; }
            public string objectclass { get; set; }
            public string iscriticalsystemobject { get; set; }
            public string usncreated { get; set; }
            public string dscorepropagationdata { get; set; }
            public string adspath { get; set; }
            public string countrycode { get; set; }
            public string primarygroupid { get; set; }
            public string objectguid { get; set; }
            public DateTime lastlogontimestamp { get; set; }
            public string msds_supportedencryptiontypes { get; set; }
            public string showinadvancedviewonly { get; set; }

            public override string ToString()
            {
                string output = "";
                if (this.samaccountname != null && this.samaccountname.Trim() != "") { output += "samaccountname: " + this.samaccountname + Environment.NewLine; }
                if (this.samaccounttype.ToString().Trim() != "") { output += "samaccounttype: " + this.samaccounttype + Environment.NewLine; }
                if (this.distinguishedname != null && this.distinguishedname.Trim() != "") { output += "distinguishedname: " + this.distinguishedname + Environment.NewLine; }
                if (this.cn != null && this.cn.Trim() != "") { output += "cn: " + this.cn + Environment.NewLine; }
                if (this.objectsid != null && this.objectsid.Trim() != "") { output += "objectsid: " + this.objectsid + Environment.NewLine; }
                if (this.sidhistory != null && String.Join(", ", this.sidhistory).Trim() != "") { output += "sidhistory: " + (this.sidhistory == null ? "" : String.Join(", ", this.sidhistory)) + Environment.NewLine; }
                if (this.grouptype.ToString().Trim() != "") { output += "grouptype: " + this.grouptype + Environment.NewLine; }
                if (this.Owner != null && this.Owner.ToString().Trim() != "") { output += "Owner: " + this.Owner + Environment.NewLine; }
                if (this.Group != null && this.Group.ToString().Trim() != "") { output += "Group: " + this.Group + Environment.NewLine; }
                if (this.DiscretionaryAcl != null && this.DiscretionaryAcl.ToString().Trim() != "") { output += "DiscretionaryAcl: " + this.DiscretionaryAcl + Environment.NewLine; }
                if (this.SystemAcl != null && this.SystemAcl.ToString().Trim() != "") { output += "SystemAcl: " + this.SystemAcl + Environment.NewLine; }
                if (this.admincount != null && this.admincount.Trim() != "") { output += "admincount: " + this.admincount + Environment.NewLine; }
                if (this.serviceprincipalname != null && this.serviceprincipalname.Trim() != "") { output += "serviceprincipalname: " + this.serviceprincipalname + Environment.NewLine; }
                if (this.name != null && this.name.Trim() != "") { output += "name: " + this.name + Environment.NewLine; }
                if (this.description != null && this.description.Trim() != "") { output += "description: " + this.description + Environment.NewLine; }
                if (this.memberof != null && this.memberof.Trim() != "") { output += "memberof: " + this.memberof + Environment.NewLine; }
                if (this.logoncount != null && this.logoncount.Trim() != "") { output += "logoncount: " + this.logoncount + Environment.NewLine; }
                if (this.useraccountcontrol.ToString().Trim() != "") { output += "useraccountcontrol: " + this.useraccountcontrol + Environment.NewLine; }
                if (this.badpwdcount != null && this.badpwdcount.Trim() != "") { output += "badpwdcount: " + this.badpwdcount + Environment.NewLine; }
                if (this.badpasswordtime != null && this.badpasswordtime.ToString().Trim() != "") { output += "badpasswordtime: " + this.badpasswordtime + Environment.NewLine; }
                if (this.pwdlastset != null && this.pwdlastset.ToString().Trim() != "") { output += "pwdlastset: " + this.pwdlastset + Environment.NewLine; }
                if (this.whencreated != null && this.whencreated.ToString().Trim() != "") { output += "whencreated: " + this.whencreated + Environment.NewLine; }
                if (this.whenchanged != null && this.whenchanged.ToString().Trim() != "") { output += "whenchanged: " + this.whenchanged + Environment.NewLine; }
                if (this.accountexpires != null && this.accountexpires.ToString().Trim() != "") { output += "accountexpires: " + this.accountexpires + Environment.NewLine; }
                if (this.lastlogon != null && this.lastlogon.ToString().Trim() != "") { output += "lastlogon: " + this.lastlogon + Environment.NewLine; }
                if (this.lastlogoff != null && this.lastlogoff.ToString().Trim() != "") { output += "lastlogoff: " + this.lastlogoff + Environment.NewLine; }
                if (this.codepage != null && this.codepage.Trim() != "") { output += "codepage: " + this.codepage + Environment.NewLine; }
                if (this.objectcategory != null && this.objectcategory.Trim() != "") { output += "objectcategory: " + this.objectcategory + Environment.NewLine; }
                if (this.usnchanged != null && this.usnchanged.Trim() != "") { output += "usnchanged: " + this.usnchanged + Environment.NewLine; }
                if (this.instancetype != null && this.instancetype.Trim() != "") { output += "instancetype: " + this.instancetype + Environment.NewLine; }
                if (this.objectclass != null && this.objectclass.Trim() != "") { output += "objectclass: " + this.objectclass + Environment.NewLine; }
                if (this.iscriticalsystemobject != null && this.iscriticalsystemobject.Trim() != "") { output += "iscriticalsystemobject: " + this.iscriticalsystemobject + Environment.NewLine; }
                if (this.usncreated != null && this.usncreated.Trim() != "") { output += "usncreated: " + this.usncreated + Environment.NewLine; }
                if (this.dscorepropagationdata != null && this.dscorepropagationdata.Trim() != "") { output += "dscorepropagationdata: " + this.dscorepropagationdata + Environment.NewLine; }
                if (this.adspath != null && this.adspath.Trim() != "") { output += "adspath: " + this.adspath + Environment.NewLine; }
                if (this.countrycode != null && this.countrycode.Trim() != "") { output += "countrycode: " + this.countrycode + Environment.NewLine; }
                if (this.primarygroupid != null && this.primarygroupid.Trim() != "") { output += "primarygroupid: " + this.primarygroupid + Environment.NewLine; }
                if (this.objectguid != null && this.objectguid.Trim() != "") { output += "objectguid: " + this.objectguid + Environment.NewLine; }
                if (this.lastlogontimestamp != null && this.lastlogontimestamp.ToString().Trim() != "") { output += "lastlogontimestamp: " + this.lastlogontimestamp + Environment.NewLine; }
                if (this.msds_supportedencryptiontypes != null && this.msds_supportedencryptiontypes.Trim() != "") { output += "msds_supportedencryptiontypes: " + this.msds_supportedencryptiontypes + Environment.NewLine; }
                if (this.showinadvancedviewonly != null && this.showinadvancedviewonly.Trim() != "") { output += "showinadvancedviewonly: " + this.showinadvancedviewonly + Environment.NewLine; }

                return output;
            }
        }

        /// <summary>
        /// SPNTicket for a DomainObject with a SPN set. Useful for obtaining krb5tgs hashes.
        /// </summary>
        public class SPNTicket
        {
            public string ServicePrincipleName { get; set; }
            public string SamAccountName { get; set; }
            public string UserDomain { get; set; }
            public string TicketByteHexStream { get; set; } = null;
            public string Hash { get; set; } = null;

            /// <summary>
            /// Constructor for SPNTicket.
            /// </summary>
            /// <param name="servicePrincipalName">Service Principal Name (SPN) for which the ticket applies.</param>
            /// <param name="samAccountName">SamAccountName for the user that has a SPN set.</param>
            /// <param name="userDomain">Domain name for the user that has a SPN set.</param>
            /// <param name="ticketHexStream">TicketHexStream of the SPNTicket.</param>
            public SPNTicket(string servicePrincipalName, string samAccountName, string userDomain, string ticketHexStream)
            {
                this.ServicePrincipleName = servicePrincipalName;
                this.SamAccountName = samAccountName;
                this.UserDomain = userDomain;
                this.TicketByteHexStream = ticketHexStream;
                var matches = Regex.Match(ticketHexStream, "a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)", RegexOptions.IgnoreCase);
                if (matches.Success)
                {
                    byte etype = Convert.ToByte(matches.Groups["EtypeLen"].Value, 16);
                    int cipherTextLen = Convert.ToInt32(matches.Groups["CipherTextLen"].Value, 16) - 4;
                    string cipherText = matches.Groups["DataToEnd"].Value.Substring(0, cipherTextLen * 2);

                    if (matches.Groups["DataToEnd"].Value.Substring(cipherTextLen * 2, 4) == "A482")
                    {
                        this.Hash = cipherText.Substring(0, 32) + "$" + cipherText.Substring(32);
                    }
                }
            }
            public enum HashFormat
            {
                Hashcat,
                John
            }

            /// <summary>
            /// Gets a krb5tgs hash formatted for a cracker.
            /// </summary>
            /// <param name="format">Format for the hash.</param>
            /// <returns>Formatted krb5tgs hash.</returns>
            public string GetFormattedHash(HashFormat format = HashFormat.Hashcat)
            {
                if (format == HashFormat.Hashcat)
                {
                    return "$krb5tgs$" + "23" + "$*" + this.SamAccountName + "$" + this.UserDomain + "$" + this.ServicePrincipleName + "$" + this.Hash;
                }
                else if (format == HashFormat.John)
                {
                    return "$krb5tgs$" + this.ServicePrincipleName + ":" + this.Hash;
                }
                return null;
            }
        }

        public enum NameType
        {
            DN = 1,
            Canonical = 2,
            NT4 = 3,
            Display = 4,
            DomainSimple = 5,
            EnterpriseSimple = 6,
            GUID = 7,
            Unknown = 8,
            UPN = 9,
            CanonicalEx = 10,
            SPN = 11,
            SID = 12
        }

        public enum SamAccountTypeEnum : uint
        {
            DOMAIN_OBJECT = 0x00000000,
            GROUP_OBJECT = 0x10000000,
            NON_SECURITY_GROUP_OBJECT = 0x10000001,
            ALIAS_OBJECT = 0x20000000,
            NON_SECURITY_ALIAS_OBJECT = 0x20000001,
            USER_OBJECT = 0x30000000,
            MACHINE_ACCOUNT = 0x30000001,
            TRUST_ACCOUNT = 0x30000002,
            APP_BASIC_GROUP = 0x40000000,
            APP_QUERY_GROUP = 0x40000001,
            ACCOUNT_TYPE_MAX = 0x7fffffff
        }

        [Flags]
        public enum GroupTypeEnum : uint
        {
            CREATED_BY_SYSTEM = 0x00000001,
            GLOBAL_SCOPE = 0x00000002,
            DOMAIN_LOCAL_SCOPE = 0x00000004,
            UNIVERSAL_SCOPE = 0x00000008,
            APP_BASIC = 0x00000010,
            APP_QUERY = 0x00000020,
            SECURITY = 0x80000000
        }

        [Flags]
        public enum UACEnum : uint
        {
            SCRIPT = 1,
            ACCOUNTDISABLE = 2,
            HOMEDIR_REQUIRED = 8,
            LOCKOUT = 16,
            PASSWD_NOTREQD = 32,
            PASSWD_CANT_CHANGE = 64,
            ENCRYPTED_TEXT_PWD_ALLOWED = 128,
            TEMP_DUPLICATE_ACCOUNT = 256,
            NORMAL_ACCOUNT = 512,
            INTERDOMAIN_TRUST_ACCOUNT = 2048,
            WORKSTATION_TRUST_ACCOUNT = 4096,
            SERVER_TRUST_ACCOUNT = 8192,
            DONT_EXPIRE_PASSWORD = 65536,
            MNS_LOGON_ACCOUNT = 131072,
            SMARTCARD_REQUIRED = 262144,
            TRUSTED_FOR_DELEGATION = 524288,
            NOT_DELEGATED = 1048576,
            USE_DES_KEY_ONLY = 2097152,
            DONT_REQ_PREAUTH = 4194304,
            PASSWORD_EXPIRED = 8388608,
            TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216,
            PARTIAL_SECRETS_ACCOUNT = 67108864
        }
    }

    /// <summary>
    /// Net is a library for localgroup/domain enumeration that can be used to search for users, groups, loggedonusers,
    /// and sessions on remote systems using Win32 API functions.
    /// </summary>
    /// <remarks>
    /// Net is adapted from Will Schroeder's (@harmj0y) PowerView. (Found
    /// at https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)
    /// </remarks>
    public static class Net
    {
        /// <summary>
        /// LocalGroup represents a local group object on a remote system.
        /// </summary>
        public class LocalGroup
        {
            public string ComputerName { get; set; } = "";
            public string GroupName { get; set; } = "";
            public string Comment { get; set; } = "";

            public override string ToString()
            {
                string output = "";
                output += "ComputerName: " + ComputerName + Environment.NewLine;
                output += "GroupName: " + GroupName + Environment.NewLine;
                output += "Comment: " + Comment + Environment.NewLine;
                return output;
            }
        }

        /// <summary>
        /// LocalGroupMember represents a user's membership to a local group on a remote system.
        /// </summary>
        public class LocalGroupMember
        {
            public string ComputerName { get; set; } = "";
            public string GroupName { get; set; } = "";
            public string MemberName { get; set; } = "";
            public string SID { get; set; } = "";
            public bool IsGroup { get; set; } = false;
            public bool IsDomain { get; set; } = false;

            public override string ToString()
            {
                string output = "";
                if (this.ComputerName.Trim() != "") { output += "ComputerName: " + ComputerName + Environment.NewLine; }
                if (this.MemberName.Trim() != "") { output += "MemberName: " + MemberName + Environment.NewLine; }
                if (this.SID.Trim() != "") { output += "SID: " + SID + Environment.NewLine; }
                if (this.IsGroup.ToString().Trim() != "") { output += "IsGroup: " + IsGroup + Environment.NewLine; }
                if (this.IsDomain.ToString().Trim() != "") { output += "IsDomain: " + IsDomain + Environment.NewLine; }

                return output;
            }
        }

        /// <summary>
        /// LoggedOnUser represents a user logged on to a remote system.
        /// </summary>
        public class LoggedOnUser
        {
            public string UserName { get; set; } = "";
            public string ComputerName { get; set; } = "";
            public string LogonDomain { get; set; } = "";
            public string AuthDomains { get; set; } = "";
            public string LogonServer { get; set; } = "";

            public override string ToString()
            {
                string output = "";
                if (this.UserName.Trim() != "") { output += "UserName: " + UserName + Environment.NewLine; }
                if (this.ComputerName.Trim() != "") { output += "ComputerName: " + ComputerName + Environment.NewLine; }
                if (this.LogonDomain.Trim() != "") { output += "LogonDomain: " + LogonDomain + Environment.NewLine; }
                if (this.AuthDomains.Trim() != "") { output += "AuthDomains: " + AuthDomains + Environment.NewLine; }
                if (this.LogonServer.Trim() != "") { output += "LogonServer: " + LogonServer + Environment.NewLine; }

                return output;
            }
        }

        /// <summary>
        /// SessionInfo represents a user with a session on a remote system.
        /// </summary>
        public class SessionInfo
        {
            public string CName { get; set; } = "";
            public string UserName { get; set; } = "";
            public string ComputerName { get; set; } = "";
            public int Time { get; set; } = 0;
            public int IdleTime { get; set; } = 0;

            public override string ToString()
            {
                string output = "";
                if (this.CName.Trim() != "") { output += "CName: " + CName + Environment.NewLine; }
                if (this.UserName.Trim() != "") { output += "UserName: " + UserName + Environment.NewLine; }
                if (this.ComputerName.Trim() != "") { output += "ComputerName: " + ComputerName + Environment.NewLine; }
                if (this.Time.ToString().Trim() != "") { output += "Time: " + Time + Environment.NewLine; }
                if (this.IdleTime.ToString().Trim() != "") { output += "IdleTime: " + IdleTime + Environment.NewLine; }

                return output;
            }
        }

        /// <summary>
        /// Gets a list of `LocalGroup`s from a specified DomainCompter.
        /// </summary>
        /// <param name="DomainComputer">DomainComputer to query for LocalGroups.</param>
        /// <param name="Credential">Credential to use for authentication to the DomainComputer.</param>
        /// <returns>List of LocalGroups.</returns>
        public static List<LocalGroup> GetNetLocalGroups(Domain.DomainObject DomainComputer, Domain.Credential Credential = null)
        {
            List<string> ComputerNames = new List<string>();
            if (DomainComputer != null && DomainComputer.samaccounttype == Domain.SamAccountTypeEnum.MACHINE_ACCOUNT)
            {
                ComputerNames.Add(DomainComputer.cn);
            }
            return ComputerNames.Count == 0 ? new List<LocalGroup>() : GetNetLocalGroups(ComputerNames, Credential);
        }

        /// <summary>
        /// Gets a list of `LocalGroup`s from specified DomainComputers.
        /// </summary>
        /// <param name="DomainComputers">List of DomainComputers to query for LocalGroups.</param>
        /// <param name="Credential">Credential to use for authentication to the DomainComputer.</param>
        /// <returns>List of LocalGroups.</returns>
        public static List<LocalGroup> GetNetLocalGroups(IEnumerable<Domain.DomainObject> DomainComputers, Domain.Credential Credential = null)
        {
            List<string> ComputerNames = new List<string>();
            foreach (Domain.DomainObject DomainComputer in DomainComputers)
            {
                if (DomainComputer != null && DomainComputer.samaccounttype == Domain.SamAccountTypeEnum.MACHINE_ACCOUNT)
                {
                    ComputerNames.Add(DomainComputer.cn);
                }
            }
            return ComputerNames.Count == 0 ? new List<LocalGroup>() : GetNetLocalGroups(ComputerNames, Credential);
        }

        /// <summary>
        /// Gets a list of `LocalGroup`s from specified remote computer(s).
        /// </summary>
        /// <param name="ComputerName">ComputerName to query for LocalGroups.</param>
        /// <param name="Credential">Credential to use for authentication to the ComputerName.</param>
        /// <returns>List of LocalGroups.</returns>
        public static List<LocalGroup> GetNetLocalGroups(string ComputerName = "127.0.0.1", Domain.Credential Credential = null)
        {
            return ComputerName == null ? new List<LocalGroup>() : GetNetLocalGroups(new List<string> { ComputerName }, Credential);
        }

        /// <summary>
        /// Gets a list of `LocalGroup`s from specified remote computer(s).
        /// </summary>
        /// <param name="ComputerNames">List of ComputerNames to query for LocalGroups.</param>
        /// <param name="Credential">Credential to use for authentication to the ComputerNames.</param>
        /// <returns>List of LocalGroups.</returns>
        public static List<LocalGroup> GetNetLocalGroups(IEnumerable<string> ComputerNames, Domain.Credential Credential = null)
        {
            ComputerNames = ComputerNames.Where(CN => CN != null);
            List<LocalGroup> localGroups = new List<LocalGroup>();
            foreach (string ComputerName in ComputerNames)
            {
                int QueryLevel = 1;
                IntPtr PtrInfo = IntPtr.Zero;
                int EntriesRead = 0;
                int TotalRead = 0;
                int ResumeHandle = 0;
                int Result = Win32.Netapi32.NetLocalGroupEnum(ComputerName, QueryLevel, out PtrInfo, -1, out EntriesRead, out TotalRead, ref ResumeHandle);
                long Offset = PtrInfo.ToInt64();
                if (Result == 0 && Offset > 0)
                {
                    int increment = Marshal.SizeOf(typeof(Win32.Netapi32.LOCALGROUP_USERS_INFO_1));
                    for (int i = 0; i < EntriesRead; i++)
                    {
                        IntPtr NextIntPtr = new IntPtr(Offset);
                        Win32.Netapi32.LOCALGROUP_USERS_INFO_1 Info = (Win32.Netapi32.LOCALGROUP_USERS_INFO_1)Marshal.PtrToStructure(NextIntPtr, typeof(Win32.Netapi32.LOCALGROUP_USERS_INFO_1));
                        Offset = NextIntPtr.ToInt64();
                        Offset += increment;
                        localGroups.Add(
                            new LocalGroup
                            {
                                ComputerName = ComputerName,
                                GroupName = Info.name,
                                Comment = Info.comment
                            }
                        );
                    }
                    Win32.Netapi32.NetApiBufferFree(PtrInfo);
                }
                else
                {
                    Console.Error.WriteLine("Error: " + new System.ComponentModel.Win32Exception(Result).Message);
                }
            }
            return localGroups;
        }

        /// <summary>
        /// Gets a list of `LocalGroupMember`s from a specified DomainComputer for a specified group.
        /// </summary>
        /// <param name="DomainComputer">DomainComputer to query for LocalGroupMembers.</param>
        /// <param name="GroupName">Group to search for LocalGroupMembers. Administrators, by default.</param>
        /// <param name="Credential">Credential to authenticate to the DomainComputer.</param>
        /// <returns>List of LocalGroupMembers</returns>
        public static List<LocalGroupMember> GetNetLocalGroupMembers(Domain.DomainObject DomainComputer, string GroupName = "Administrators", Domain.Credential Credential = null)
        {
            List<string> ComputerNames = new List<string>();
            if (DomainComputer != null && DomainComputer.samaccounttype == Domain.SamAccountTypeEnum.MACHINE_ACCOUNT)
            {
                ComputerNames.Add(DomainComputer.cn);
            }
            return ComputerNames.Count == 0 || GroupName == null ? new List<LocalGroupMember>() : GetNetLocalGroupMembers(ComputerNames, GroupName, Credential);
        }

        /// <summary>
        /// Gets a list of `LocalGroupMember`s from specified DomainComputers for a specified group.
        /// </summary>
        /// <param name="DomainComputers">DomainComputers to query for LocalGroupMembers.</param>
        /// <param name="GroupName">Group to search for LocalGroupMembers. Administrators, by default.</param>
        /// <param name="Credential">Credential to authenticate to the DomainComputer.</param>
        /// <returns>List of LocalGroupMembers.</returns>
        public static List<LocalGroupMember> GetNetLocalGroupMembers(IEnumerable<Domain.DomainObject> DomainComputers, string GroupName = "Administrators", Domain.Credential Credential = null)
        {
            List<string> ComputerNames = new List<string>();
            foreach (Domain.DomainObject DomainComputer in DomainComputers)
            {
                if (DomainComputer != null && DomainComputer.samaccounttype == Domain.SamAccountTypeEnum.MACHINE_ACCOUNT)
                {
                    ComputerNames.Add(DomainComputer.cn);
                }
            }
            return ComputerNames.Count == 0 || GroupName == null ? new List<LocalGroupMember>() : GetNetLocalGroupMembers(ComputerNames, GroupName, Credential);
        }

        /// <summary>
        /// Gets a list of `LocalGroupMember`s from a specified ComputerName for a specified group.
        /// </summary>
        /// <param name="ComputerName">ComputerName to query for LocalGroupMembers.</param>
        /// <param name="GroupName">Group to search for LocalGroupMembers. Administrators, by default.</param>
        /// <param name="Credential">Credential to authenticate to the ComputerName.</param>
        /// <returns>List of LocalGroupMembers.</returns>
        public static List<LocalGroupMember> GetNetLocalGroupMembers(string ComputerName = "127.0.0.1", string GroupName = "Administrators", Domain.Credential Credential = null)
        {
            return ComputerName == null || GroupName == null ? new List<LocalGroupMember>() : GetNetLocalGroupMembers(new List<string> { ComputerName }, GroupName, Credential);
        }

        /// <summary>
        /// Gets a list of `LocalGroupMember`s from specified ComputerNames for a specified group.
        /// </summary>
        /// <param name="ComputerNames">List of ComputerNames to query for LocalGroupMembers.</param>
        /// <param name="GroupName">Group to search for LocalGroupMembers. Administrators, by default.</param>
        /// <param name="Credential">Credential to authenticate to the ComputerNames.</param>
        /// <returns>List of LocalGroupMembers</returns>
        public static List<LocalGroupMember> GetNetLocalGroupMembers(IEnumerable<string> ComputerNames, string GroupName = "Administrators", Domain.Credential Credential = null)
        {
            ComputerNames = ComputerNames.Where(CN => CN != null);
            List<LocalGroupMember> groupMembers = new List<LocalGroupMember>();
            foreach (string ComputerName in ComputerNames)
            {
                int QueryLevel = 2;
                IntPtr PtrInfo = IntPtr.Zero;
                int EntriesRead = 0;
                int TotalRead = 0;
                int ResumeHandle = 0;
                int Result = Win32.Netapi32.NetLocalGroupGetMembers(ComputerName, GroupName, QueryLevel, out PtrInfo, -1, out EntriesRead, out TotalRead, ref ResumeHandle);
                long Offset = PtrInfo.ToInt64();
                if (Result == 0 && Offset > 0)
                {
                    int increment = Marshal.SizeOf(typeof(Win32.Netapi32.LOCALGROUP_MEMBERS_INFO_2));
                    for (int i = 0; i < EntriesRead; i++)
                    {
                        IntPtr NextIntPtr = new IntPtr(Offset);
                        Win32.Netapi32.LOCALGROUP_MEMBERS_INFO_2 Info = (Win32.Netapi32.LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(NextIntPtr, typeof(Win32.Netapi32.LOCALGROUP_MEMBERS_INFO_2));
                        Offset = NextIntPtr.ToInt64();
                        Offset += increment;

                        IntPtr ptrSid;
                        bool Result2 = Win32.Advapi32.ConvertSidToStringSid(Info.lgrmi2_sid, out ptrSid);
                        if (!Result2)
                        {
                            int LastError = Marshal.GetLastWin32Error();
                            Console.Error.WriteLine("Error: " + new System.ComponentModel.Win32Exception(LastError).Message);
                        }
                        else
                        {
                            string SidString = "";
                            try
                            {
                                SidString = Marshal.PtrToStringAuto(ptrSid);
                            }
                            finally
                            {
                                Win32.Kernel32.LocalFree(ptrSid);
                            }

                            groupMembers.Add(
                                new LocalGroupMember
                                {
                                    ComputerName = ComputerName,
                                    GroupName = GroupName,
                                    MemberName = Info.lgrmi2_domainandname,
                                    SID = SidString,
                                    IsGroup = Info.lgrmi2_sidusage == (UInt16)Win32.Netapi32.SID_NAME_USE.SidTypeGroup,
                                    IsDomain = false
                                }
                            );
                        }
                    }
                    Win32.Netapi32.NetApiBufferFree(PtrInfo);

                    Regex localUserRegex = new Regex(".*-500");
                    Regex localUserRegex2 = new Regex(".*-501");
                    LocalGroupMember localMachineUser = groupMembers.FirstOrDefault(GM => localUserRegex.IsMatch(GM.SID) || localUserRegex2.IsMatch(GM.SID));
                    if (localMachineUser != null)
                    {
                        string MachineSID = localMachineUser.SID.Substring(0, localMachineUser.SID.LastIndexOf("-"));
                        foreach (LocalGroupMember member in groupMembers)
                        {
                            if (member.SID.Contains(MachineSID))
                            {
                                member.IsDomain = true;
                            }
                        }
                    }
                }
                else
                {
                    Console.Error.WriteLine("Error: " + new System.ComponentModel.Win32Exception(Result).Message);
                }
            }
            return groupMembers;
        }

        /// <summary>
        /// Gets a list of `LoggedOnUser`s from a DomainComputer.
        /// </summary>
        /// <param name="DomainComputer">DomainComputer to query for LoggedOnUsers</param>
        /// <param name="Credential">Credentials to authenticate to the DomainComputer.</param>
        /// <returns>List of LoggedOnUsers.</returns>
        public static List<LoggedOnUser> GetNetLoggedOnUsers(Domain.DomainObject DomainComputer, Domain.Credential Credential = null)
        {
            List<string> ComputerNames = new List<string>();
            if (DomainComputer != null && DomainComputer.samaccounttype == Domain.SamAccountTypeEnum.MACHINE_ACCOUNT)
            {
                ComputerNames.Add(DomainComputer.cn);
            }
            return ComputerNames.Count == 0 ? new List<LoggedOnUser>() : GetNetLoggedOnUsers(ComputerNames, Credential);
        }

        /// <summary>
        /// Gets a list of `LoggedOnUser`s from a list of DomainComputers.
        /// </summary>
        /// <param name="DomainComputers">DomainComputers to query for LoggedOnUsers.</param>
        /// <param name="Credential">Credentials to authenticate to the DomainComputers.</param>
        /// <returns>List of LoggedOnUsers.</returns>
        public static List<LoggedOnUser> GetNetLoggedOnUsers(IEnumerable<Domain.DomainObject> DomainComputers, Domain.Credential Credential = null)
        {
            List<string> ComputerNames = new List<string>();
            foreach (Domain.DomainObject DomainComputer in DomainComputers)
            {
                if (DomainComputer != null && DomainComputer.samaccounttype == Domain.SamAccountTypeEnum.MACHINE_ACCOUNT)
                {
                    ComputerNames.Add(DomainComputer.cn);
                }
            }
            return ComputerNames.Count == 0 ? new List<LoggedOnUser>() : GetNetLoggedOnUsers(ComputerNames, Credential);
        }

        /// <summary>
        /// Gets a list of `LoggedOnUser`s from a ComputerName.
        /// </summary>
        /// <param name="ComputerName">ComputerName to query for LoggedOnUsers.</param>
        /// <param name="Credential">Credentials to authenticate to the ComputerName.</param>
        /// <returns>List of LoggedOnUsers.</returns>
        public static List<LoggedOnUser> GetNetLoggedOnUsers(string ComputerName = "127.0.0.1", Domain.Credential Credential = null)
        {
            return ComputerName == null ? new List<LoggedOnUser>() : GetNetLoggedOnUsers(new List<string> { ComputerName }, Credential);
        }

        /// <summary>
        /// Gets a list of `LoggedOnUser`s from a list of ComputerNames.
        /// </summary>
        /// <param name="ComputerNames">ComputerNames to query for LoggedOnUsers.</param>
        /// <param name="Credential">Credentials to authenticate to the ComputerNames.</param>
        /// <returns>List of LoggedOnUsers.</returns>
        public static List<LoggedOnUser> GetNetLoggedOnUsers(IEnumerable<string> ComputerNames, Domain.Credential Credential = null)
        {
            ComputerNames = ComputerNames.Where(CN => CN != null);
            List<LoggedOnUser> loggedOnUsers = new List<LoggedOnUser>();
            foreach (string ComputerName in ComputerNames)
            {
                int QueryLevel = 1;
                IntPtr PtrInfo = IntPtr.Zero;
                int EntriesRead = 0;
                int TotalRead = 0;
                int ResumeHandle = 0;

                int Result = Win32.Netapi32.NetWkstaUserEnum(ComputerName, QueryLevel, out PtrInfo, -1, out EntriesRead, out TotalRead, ref ResumeHandle);
                long Offset = PtrInfo.ToInt64();

                if (Result == 0 && Offset > 0)
                {
                    int increment = Marshal.SizeOf(typeof(Win32.Netapi32.WKSTA_USER_INFO_1));
                    for (int i = 0; i < EntriesRead; i++)
                    {
                        IntPtr NextIntPtr = new IntPtr(Offset);
                        Win32.Netapi32.WKSTA_USER_INFO_1 Info = (Win32.Netapi32.WKSTA_USER_INFO_1)Marshal.PtrToStructure(NextIntPtr, typeof(Win32.Netapi32.WKSTA_USER_INFO_1));
                        Offset = NextIntPtr.ToInt64();
                        Offset += increment;

                        loggedOnUsers.Add(
                            new LoggedOnUser
                            {
                                UserName = Info.wkui1_username,
                                ComputerName = ComputerName,
                                LogonDomain = Info.wkui1_logon_domain,
                                AuthDomains = Info.wkui1_oth_domains,
                                LogonServer = Info.wkui1_logon_server
                            }
                        );
                    }
                    Win32.Netapi32.NetApiBufferFree(PtrInfo);
                }
                else
                {
                    Console.Error.WriteLine("Error: " + new System.ComponentModel.Win32Exception(Result).Message);
                }
            }
            return loggedOnUsers;
        }

        /// <summary>
        /// Gets a list of `SessionInfo`s from a DomainComputer.
        /// </summary>
        /// <param name="DomainComputer">DomainComputer to query for SessionInfos.</param>
        /// <param name="Credential">Credentials to authenticate to the DomainComputer.</param>
        /// <returns>List of SessionInfos.</returns>
        public static List<SessionInfo> GetNetSessions(Domain.DomainObject DomainComputer, Domain.Credential Credential = null)
        {
            List<string> ComputerNames = new List<string>();
            if (DomainComputer != null && DomainComputer.samaccounttype == Domain.SamAccountTypeEnum.MACHINE_ACCOUNT)
            {
                ComputerNames.Add(DomainComputer.cn);
            }
            return ComputerNames.Count == 0 ? new List<SessionInfo>() : GetNetSessions(ComputerNames, Credential);
        }

        /// <summary>
        /// Gets a list of `SessionInfo`s from a list of DomainComputers.
        /// </summary>
        /// <param name="DomainComputers">DomainComputers to query for SessionInfos.</param>
        /// <param name="Credential">Credentials to authenticate to the DomainComputers.</param>
        /// <returns>List of SessionInfos.</returns>
        public static List<SessionInfo> GetNetSessions(IEnumerable<Domain.DomainObject> DomainComputers, Domain.Credential Credential = null)
        {
            List<string> ComputerNames = new List<string>();
            foreach (Domain.DomainObject DomainComputer in DomainComputers)
            {
                if (DomainComputer != null && DomainComputer.samaccounttype == Domain.SamAccountTypeEnum.MACHINE_ACCOUNT)
                {
                    ComputerNames.Add(DomainComputer.cn);
                }
            }
            return ComputerNames.Count == 0 ? new List<SessionInfo>() : GetNetSessions(ComputerNames, Credential);
        }

        /// <summary>
        /// Gets a list of `SessionInfo`s from a ComputerName.
        /// </summary>
        /// <param name="ComputerName">ComputerName to query for SessionInfos.</param>
        /// <param name="Credential">Credentials to authenticate to the ComputerName.</param>
        /// <returns>List of SessionInfos.</returns>
        public static List<SessionInfo> GetNetSessions(string ComputerName = "127.0.0.1", Domain.Credential Credential = null)
        {
            return ComputerName == null ? new List<SessionInfo>() : GetNetSessions(new List<string> { ComputerName }, Credential);
        }

        /// <summary>
        /// Gets a list of `SessionInfo`s from a list of ComputerNames.
        /// </summary>
        /// <param name="ComputerNames">ComputerNames to query for SessionInfos.</param>
        /// <param name="Credential">Credentials to authenticate to the ComputerNames.</param>
        /// <returns>List of SessionInfos.</returns>
        public static List<SessionInfo> GetNetSessions(IEnumerable<string> ComputerNames, Domain.Credential Credential = null)
        {
            ComputerNames = ComputerNames.Where(CN => CN != null);
            List<SessionInfo> sessions = new List<SessionInfo>();
            foreach (string ComputerName in ComputerNames)
            {
                int QueryLevel = 10;
                IntPtr PtrInfo = IntPtr.Zero;
                int EntriesRead = 0;
                int TotalRead = 0;
                int ResumeHandle = 0;

                int Result = Win32.Netapi32.NetSessionEnum(ComputerName, null, null, QueryLevel, out PtrInfo, -1, out EntriesRead, out TotalRead, ref ResumeHandle);
                long Offset = PtrInfo.ToInt64();
                if (Result == 0 && Offset > 0)
                {
                    int increment = Marshal.SizeOf(typeof(Win32.Netapi32.SESSION_INFO_10));
                    for (int i = 0; i < EntriesRead; i++)
                    {
                        IntPtr NextIntPtr = new IntPtr(Offset);
                        Win32.Netapi32.SESSION_INFO_10 Info = (Win32.Netapi32.SESSION_INFO_10)Marshal.PtrToStructure(NextIntPtr, typeof(Win32.Netapi32.SESSION_INFO_10));
                        Offset += increment;

                        sessions.Add(
                            new SessionInfo
                            {
                                CName = Info.sesi10_cname,
                                UserName = Info.sesi10_username,
                                ComputerName = ComputerName,
                                Time = Info.sesi10_time,
                                IdleTime = Info.sesi10_idle_time
                            }
                        );
                    }
                    Win32.Netapi32.NetApiBufferFree(PtrInfo);
                }
                else
                {
                    Console.Error.WriteLine("Error: " + new System.ComponentModel.Win32Exception(Result).Message);
                }
            }
            return sessions;
        }
    }
}
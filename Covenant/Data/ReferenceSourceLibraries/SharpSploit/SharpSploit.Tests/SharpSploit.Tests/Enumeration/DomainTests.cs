// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Enumeration;

namespace SharpSploit.Tests.Enumeration
{
    [TestClass]
    public class DomainTests
    {
        [TestMethod]
        public void TestGetUsers()
        {
            Domain.DomainSearcher searcher = new Domain.DomainSearcher();
            IList<Domain.DomainObject> users = searcher.GetDomainUsers();
            foreach (Domain.DomainObject user in users)
            {
                Assert.IsTrue(user.distinguishedname.ToLower().Contains(Environment.UserDomainName.ToLower()));
            }
            Assert.AreEqual(1, users.Where(U => U.samaccountname == "krbtgt").ToList().Count());
        }

        [TestMethod]
        public void TestGetGroups()
        {
            Domain.DomainSearcher searcher = new Domain.DomainSearcher();
            IList<Domain.DomainObject> groups = searcher.GetDomainGroups();
            foreach (Domain.DomainObject group in groups)
            {
                Assert.IsTrue(group.distinguishedname.ToLower().Contains(Environment.UserDomainName.ToLower()));
            }
        }

        [TestMethod]
        public void TestGetComputers()
        {
            Domain.DomainSearcher searcher = new Domain.DomainSearcher();
            IList<Domain.DomainObject> computers = searcher.GetDomainComputers();
            foreach (Domain.DomainObject computer in computers)
            {
                Assert.IsTrue(computer.distinguishedname.ToLower().Contains(Environment.UserDomainName.ToLower()));
            }
        }

        [TestMethod]
        public void TestKerberoast()
        {
            List<Domain.SPNTicket> tickets = new Domain.DomainSearcher().Kerberoast();
            foreach (Domain.SPNTicket ticket in tickets)
            {
                Assert.AreEqual(Environment.UserDomainName, ticket.UserDomain);
            }
        }

        [TestMethod]
        public void TestGetNetLocalGroup()
        {
            List<Net.LocalGroup> groups = Net.GetNetLocalGroups(new List<string> { "COBBR-WIN10-2", "cobbr-win81", "win16" });
            List<Net.LocalGroup> groups1 = Net.GetNetLocalGroups("COBBR-WIN10-2");
            List<Net.LocalGroup> groups2 = Net.GetNetLocalGroups("cobbr-win81");
            List<Net.LocalGroup> groups3 = Net.GetNetLocalGroups("win16");
            Assert.AreEqual(groups.Count, groups1.Count + groups2.Count + groups3.Count);
            List<Net.LocalGroup> nullGroups1 = Net.GetNetLocalGroups(new List<string> { null, null, null });
            Assert.AreEqual(0, nullGroups1.Count);
            List<Net.LocalGroup> nullGroups2 = Net.GetNetLocalGroups(new List<Domain.DomainObject> { null, null, null });
            Assert.AreEqual(0, nullGroups2.Count);
        }

        [TestMethod]
        public void TestGetNetLocalGroupMembers()
        {
            List<Net.LocalGroupMember> members = Net.GetNetLocalGroupMembers(new List<string> { "COBBR-WIN10-2", "cobbr-win81", "win16" });
            List<Net.LocalGroupMember> members1 = Net.GetNetLocalGroupMembers("COBBR-WIN10-2");
            List<Net.LocalGroupMember> members2 = Net.GetNetLocalGroupMembers("cobbr-win81");
            List<Net.LocalGroupMember> members3 = Net.GetNetLocalGroupMembers("win16");
            Assert.AreEqual(members.Count, members1.Count + members2.Count + members3.Count);
            List<Net.LocalGroupMember> nullMembers1 = Net.GetNetLocalGroupMembers(new List<string> { null, null, null });
            Assert.AreEqual(0, nullMembers1.Count);
            List<Net.LocalGroupMember> nullMembers2 = Net.GetNetLocalGroupMembers(new List<Domain.DomainObject> { null, null, null });
            Assert.AreEqual(0, nullMembers2.Count);
            List<Net.LocalGroupMember> DomainComputerAdministrators = Net.GetNetLocalGroupMembers(new Domain.DomainSearcher().GetDomainComputers(new List<string> { "COBBR-WIN10-2", "cobbr-win81", "win16" }));
            Assert.IsTrue(DomainComputerAdministrators.Count >= members.Count);
        }

        [TestMethod]
        public void TestGetNetLoggedOnUsers()
        {
            List<Net.LoggedOnUser> users = Net.GetNetLoggedOnUsers(new List<string> { "COBBR-WIN10-2", "cobbr-win81", "win16" });
            List<Net.LoggedOnUser> users1 = Net.GetNetLoggedOnUsers("COBBR-WIN10-2");
            List<Net.LoggedOnUser> users2 = Net.GetNetLoggedOnUsers("cobbr-win81");
            List<Net.LoggedOnUser> users3 = Net.GetNetLoggedOnUsers("win16");
            Assert.AreEqual(users.Count, users1.Count + users2.Count + users3.Count);
            List<Net.LoggedOnUser> nullUsers1 = Net.GetNetLoggedOnUsers(new List<string> { null, null, null });
            Assert.AreEqual(0, nullUsers1.Count);
            List<Net.LoggedOnUser> nullUsers2 = Net.GetNetLoggedOnUsers(new List<Domain.DomainObject> { null, null, null });
            Assert.AreEqual(0, nullUsers2.Count);
            List<Net.LoggedOnUser> LoggedOnUsers = Net.GetNetLoggedOnUsers(new Domain.DomainSearcher().GetDomainComputers(new List<string> { "COBBR-WIN10-2", "cobbr-win81", "win16" }));
            Assert.AreEqual(LoggedOnUsers.Count, users.Count);
        }

        [TestMethod]
        public void TestGetNetSessions()
        {
            List<Net.SessionInfo> sessions = Net.GetNetSessions(new List<string> { "COBBR-WIN10-2", "cobbr-win81", "win16" });
            List<Net.SessionInfo> sessions1 = Net.GetNetSessions("COBBR-WIN10-2");
            List<Net.SessionInfo> sessions2 = Net.GetNetSessions("cobbr-win81");
            List<Net.SessionInfo> sessions3 = Net.GetNetSessions("win16");
            Assert.AreEqual(sessions.Count, sessions1.Count + sessions2.Count + sessions3.Count);
            List<Net.SessionInfo> nullSessions1 = Net.GetNetSessions(new List<string> { null, null, null });
            Assert.AreEqual(0, nullSessions1.Count);
            List<Net.SessionInfo> nullSessions2 = Net.GetNetSessions(new List<Domain.DomainObject> { null, null, null });
            Assert.AreEqual(0, nullSessions2.Count);
            List<Net.SessionInfo> DomainSessions = Net.GetNetSessions(new Domain.DomainSearcher().GetDomainComputers(new List<string> { "COBBR-WIN10-2", "cobbr-win81", "win16" }));
            Assert.AreEqual(DomainSessions.Count, sessions.Count);
        }
    }
}

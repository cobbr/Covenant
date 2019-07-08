// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.IO;
using System.Diagnostics;
using System.Security.Principal;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Credentials;

namespace SharpSploit.Tests.Credentials
{
    [TestClass]
    public class TokensTests
    {
        [TestMethod]
        public void TestImpersonateUser()
        {
            string whoami = WindowsIdentity.GetCurrent().Name;
            using (Tokens t = new Tokens())
            {
                t.ImpersonateUser("DESKTOP-F9DQ76G\\TestUser");
                //t.ImpersonateProcess(18760);
                Assert.AreEqual("DESKTOP-F9DQ76G\\TestUser".ToLower(), WindowsIdentity.GetCurrent().Name.ToLower());

                Assert.IsTrue(t.RevertToSelf());
                Assert.AreEqual(whoami.ToLower(), WindowsIdentity.GetCurrent().Name.ToLower());
            }
        }

        [TestMethod]
        public void TestGetSystem()
        {
            string whoami = WindowsIdentity.GetCurrent().Name;
            using (Tokens t = new Tokens())
            {
                Assert.IsTrue(t.GetSystem());
                Assert.AreEqual("NT AUTHORITY\\SYSTEM".ToLower(), WindowsIdentity.GetCurrent().Name.ToLower());

                Assert.IsTrue(t.RevertToSelf());
                Assert.AreEqual(whoami.ToLower(), WindowsIdentity.GetCurrent().Name.ToLower());
            }
        }

        [TestMethod]
        public void TestBypassUAC()
        {
            using (Tokens t = new Tokens())
            {
                Assert.IsFalse(this.IsElevated());
                int cmdCount = Process.GetProcessesByName("cmd").Length;
                Assert.IsTrue(t.BypassUAC());
                Assert.AreEqual(cmdCount + 1, Process.GetProcessesByName("cmd").Length);
                Assert.IsTrue(t.RevertToSelf());
            }
        }

        [TestMethod]
        public void TestMakeToken()
        {
            string whoami = WindowsIdentity.GetCurrent().Name;
            using (Tokens t = new Tokens())
            {
                Assert.IsTrue(t.MakeToken("TestUser", "DESKTOP-F9DQ76G", "TestPass123!"));
                try
                {
                    Assert.AreEqual("test", File.ReadAllText("\\\\192.168.1.230\\smb\\file.txt"));
                }
                catch (FileNotFoundException)
                {

                }

                Assert.AreEqual(whoami, WindowsIdentity.GetCurrent().Name);
                Assert.IsTrue(t.RevertToSelf());
            }
        }

        [TestMethod]
        public void TestRunAs()
        {
            string whoami = WindowsIdentity.GetCurrent().Name;
            using (Tokens t = new Tokens())
            {
                string whoaminow = t.RunAs("TestUser", "DESKTOP-F9DQ76G", "TestPass123!", () =>
                {
                    return WindowsIdentity.GetCurrent().Name;
                });
                Assert.AreNotEqual(whoami.Trim().ToLower(), whoaminow.Trim().ToLower());

                Assert.AreEqual("DESKTOP-F9DQ76G\\TestUser".Trim().ToLower(), whoaminow.Trim().ToLower());
            }
        }

        private bool IsElevated()
        {
            return Environment.UserName.ToLower() == "system" || WindowsIdentity.GetCurrent().Owner != WindowsIdentity.GetCurrent().User;
        }
    }
}

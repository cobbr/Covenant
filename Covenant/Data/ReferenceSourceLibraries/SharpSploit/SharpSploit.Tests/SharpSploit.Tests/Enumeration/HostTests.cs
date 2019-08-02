// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.IO;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Enumeration;
using SharpSploit.Generic;

namespace SharpSploit.Tests.Enumeration
{
    [TestClass]
    public class HostTests
    {
        [TestMethod]
        public void TestProcessList()
        {
            SharpSploitResultList<Host.ProcessResult> results = Host.GetProcessList();
            Assert.IsNotNull(results);
            Assert.IsTrue(results.Count > 10);
            foreach (Host.ProcessResult result in results)
            {
                Assert.IsNotNull(result);
                Assert.AreNotEqual(result.Name, "");
                Assert.IsInstanceOfType(result.Pid, typeof(int));
                Assert.IsInstanceOfType(result.Ppid, typeof(int));
            }
        }

        [TestMethod]
        public void TestProcessDump()
        {
            // Test currently failing since ProcessDump must be run as an Administrator
            File.Delete("output.dmp");
            Assert.IsFalse(File.Exists("output.dmp"));
            Host.CreateProcessDump("lsass", "", "output.dmp");
            Assert.IsTrue(File.Exists("output.dmp"));
            File.Delete("output.dmp");

            Process process = Process.GetProcessesByName("lsass")[0];

            Assert.IsFalse(File.Exists("output.dmp"));
            Host.CreateProcessDump(process.Id, "", "output.dmp");
            Assert.IsTrue(File.Exists("output.dmp"));
            File.Delete("output.dmp");

            Assert.IsFalse(File.Exists("output.dmp"));
            Host.CreateProcessDump(process, "", "output.dmp");
            Assert.IsTrue(File.Exists("output.dmp"));
            File.Delete("output.dmp");
        }

        [TestMethod]
        public void TestGetHostname()
        {
            String output = Host.GetHostname();
            Assert.IsNotNull(output);
            Assert.AreEqual(output, Environment.MachineName);
        }

        [TestMethod]
        public void TestGetUsername()
        {
            String output = Host.GetUsername();
            Assert.IsNotNull(output);
            Assert.AreEqual(output, Environment.UserDomainName + "\\" + Environment.UserName);
        }

        [TestMethod]
        public void TestGetCurrentDirectory()
        {
            String output = Host.GetCurrentDirectory();
            Assert.IsNotNull(output);
            Assert.AreEqual(output, System.IO.Directory.GetCurrentDirectory());
        }

        [TestMethod]
        public void TestGetDirectoryListing()
        {
            SharpSploitResultList<Host.FileSystemEntryResult> results = Host.GetDirectoryListing();
            Assert.IsNotNull(results);
            foreach (Host.FileSystemEntryResult result in results)
            {
                Assert.IsNotNull(result);
                Assert.AreNotEqual(result.Name, "");
            }
        }

        [TestMethod]
        public void TestChangeCurrentDirectory()
        {
            SharpSploitResultList<Host.FileSystemEntryResult> results1 = Host.GetDirectoryListing();
            string dir1 = Host.GetCurrentDirectory();
            Host.ChangeCurrentDirectory("..");
            string dir2 = Host.GetCurrentDirectory();
            Assert.AreNotEqual(dir1, dir2);
            SharpSploitResultList<Host.FileSystemEntryResult> results2 = Host.GetDirectoryListing();
            Assert.AreNotEqual(results1, results2);
        }

        [TestMethod]
        public void TestChangeCurrentDirectoryEmptyString()
        {
            SharpSploitResultList<Host.FileSystemEntryResult> results1 = Host.GetDirectoryListing();
            string dir1 = Host.GetCurrentDirectory();
            Host.ChangeCurrentDirectory("");
            string dir2 = Host.GetCurrentDirectory();
            Assert.AreEqual(dir1, dir2);
            SharpSploitResultList<Host.FileSystemEntryResult> results2 = Host.GetDirectoryListing();
            Assert.AreEqual(results1.FormatList(), results2.FormatList());
        }

        [TestMethod]
        public void TestChangeCurrentDirectoryNull()
        {
            SharpSploitResultList<Host.FileSystemEntryResult> results1 = Host.GetDirectoryListing();
            string dir1 = Host.GetCurrentDirectory();
            Host.ChangeCurrentDirectory(null);
            string dir2 = Host.GetCurrentDirectory();
            Assert.AreEqual(dir1, dir2);
            SharpSploitResultList<Host.FileSystemEntryResult> results2 = Host.GetDirectoryListing();
            Assert.AreEqual(results1.FormatList(), results2.FormatList());
        }
    }
}

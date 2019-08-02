// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Execution;

namespace SharpSploit.Tests.Execution
{
    [TestClass]
    public class ShellTest
    {
        [TestMethod]
        public void TestPowerShellExecute()
        {
            String output = Shell.PowerShellExecute("Get-ChildItem");
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output.Length > 10);
        }

        [TestMethod]
        public void TestPowerShellExecuteEmptyString()
        {
            String output = Shell.PowerShellExecute("");
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output == "");
        }

        [TestMethod]
        public void TestPowerShellExecuteNull()
        {
            String output = Shell.PowerShellExecute(null);
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output == "");
        }

        [TestMethod]
        public void TestShellExecute()
        {
            String output = Shell.ShellExecute("tasklist /v");
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output.Length > 10);
        }

        [TestMethod]
        public void TestShellExecuteEmptyString()
        {
            String output = Shell.ShellExecute("");
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output == "");
        }

        [TestMethod]
        public void TestShellExecuteNull()
        {
            String output = Shell.ShellExecute(null);
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output == "");
        }
    }
}

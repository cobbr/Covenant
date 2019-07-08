// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Enumeration;

namespace SharpSploit.Tests.Enumeration
{
    [TestClass]
    public class RegistryTests
    {
        [TestMethod]
        public void TestReadRegistry()
        {
            string path = Registry.GetRegistryKey("HKEY_CURRENT_USER\\Environment\\Path");
            Assert.IsTrue(path.Length > 2);
            string path2 = Registry.GetRegistryKey("HKCU\\Environment\\Path");
            Assert.IsTrue(path2.Length > 2);
            Assert.AreEqual(path, path2);
        }

        [TestMethod]
        public void TestWriteRegistry()
        {
            string path = Registry.GetRegistryKey("HKEY_CURRENT_USER\\Environment\\Path");
            Assert.IsTrue(path.Length > 2);
            bool success = Registry.SetRegistryKey("HKEY_CURRENT_USER\\Environment\\Path", "testing");
            Assert.IsTrue(success);
            string path2 = Registry.GetRegistryKey("HKEY_CURRENT_USER\\Environment\\Path");
            Assert.AreEqual("testing", path2);
            success = Registry.SetRegistryKey("HKEY_CURRENT_USER\\Environment\\Path", path);
            Assert.IsTrue(success);
            string path3 = Registry.GetRegistryKey("HKEY_CURRENT_USER\\Environment\\Path");
            Assert.AreEqual(path, path3);
        }
    }
}

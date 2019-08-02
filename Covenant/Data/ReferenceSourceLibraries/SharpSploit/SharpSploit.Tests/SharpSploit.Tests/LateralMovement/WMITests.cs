// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.LateralMovement;

namespace SharpSploit.Tests.LateralMovement
{
    [TestClass]
    public class WMITests
    {
        [TestMethod]
        public void TestWMIExecute()
        {
            Assert.IsTrue(WMI.WMIExecute("win16", "powershell.exe", "DEV-COBBR\\TestAdmin", "Password123!"));
        }
    }
}

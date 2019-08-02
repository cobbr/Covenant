// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.LateralMovement;

namespace SharpSploit.Tests.LateralMovement
{
    [TestClass]
    public class DCOMTests
    {
        [TestMethod]
        public void TestDCOMExecute()
        {
            Assert.IsTrue(DCOM.DCOMExecute("localhost", "calc.exe", "", "C:\\WINDOWS\\System32\\", DCOM.DCOMMethod.MMC20_Application));
            Assert.IsTrue(System.Diagnostics.Process.GetProcessesByName("Calculator").Length >= 1);
            Assert.IsTrue(DCOM.DCOMExecute("localhost", "calc.exe", "", "C:\\WINDOWS\\System32\\", DCOM.DCOMMethod.ShellBrowserWindow));
            Assert.IsTrue(System.Diagnostics.Process.GetProcessesByName("Calculator").Length >= 2);
            Assert.IsTrue(DCOM.DCOMExecute("localhost", "calc.exe", "", "C:\\WINDOWS\\System32\\", DCOM.DCOMMethod.ShellWindows));
            Assert.IsTrue(System.Diagnostics.Process.GetProcessesByName("Calculator").Length >= 3);
            Assert.IsTrue(DCOM.DCOMExecute("localhost", "calc.exe", "", "C:\\WINDOWS\\System32\\", DCOM.DCOMMethod.ExcelDDE));
            Assert.IsTrue(System.Diagnostics.Process.GetProcessesByName("Calculator").Length >= 4);
        }
    }
}

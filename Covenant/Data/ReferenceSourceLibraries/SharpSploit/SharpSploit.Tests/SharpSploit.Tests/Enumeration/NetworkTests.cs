// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Enumeration;
using SharpSploit.Generic;

namespace SharpSploit.Tests.Enumeration
{
    [TestClass]
    public class NetworkTests
    {
        [TestMethod]
        public void TestPing()
        {

            SharpSploitResultList<Network.PingResult> results = Network.Ping("127.0.0.1");
            Assert.IsNotNull(results);
            Assert.AreEqual(results.Count, 1);
            Assert.AreEqual(results[0].ComputerName, "127.0.0.1");
            Assert.IsTrue(results[0].IsUp);
        }

        [TestMethod]
        public void TestPingList()
        {
            List<string> hosts = new List<string> { "127.0.0.1", "8.8.8.8", "1.1.1.1", "google.com", "192.168.200.1" };

            SharpSploitResultList<Network.PingResult> results = Network.Ping(hosts, 10000);
            Assert.IsNotNull(results);
            Assert.AreEqual(4, results.Count);
            Assert.AreEqual(4, results.Where(R => R.IsUp).ToList().Count);
            foreach (Network.PingResult result in results)
            {
                Assert.IsNotNull(result);
                Assert.AreNotEqual(result.ComputerName, "");
                Assert.IsInstanceOfType(result.ComputerName, typeof(string));
                Assert.IsInstanceOfType(result.IsUp, typeof(bool));
            }
        }

        [TestMethod]
        public void TestPingCidrThreaded()
        {
            List<string> hosts = new List<string> { "127.0.0.1", "8.8.8.8/24" };

            SharpSploitResultList<Network.PingResult> results1 = Network.Ping(hosts, 100, 120);
            SharpSploitResultList<Network.PingResult> results2 = Network.Ping(hosts, 10000, 1);

            Assert.IsNotNull(results1);
            Assert.IsNotNull(results2);
            Assert.AreEqual(results1.Count, results2.Count);
            Assert.AreEqual(results1.Where(R => R.IsUp).ToList().Count, results2.Where(R => R.IsUp).ToList().Count);
            Assert.AreEqual(String.Join(",", results1.Select(R => R.ComputerName).OrderBy(C => C).ToArray()), String.Join(",", results2.Select(R => R.ComputerName).OrderBy(C => C).ToArray()));
            results1.AddRange(results2);
            foreach (Network.PingResult result in results1)
            {
                Assert.IsNotNull(result);
                Assert.AreNotEqual(result.ComputerName, "");
                Assert.IsInstanceOfType(result.ComputerName, typeof(string));
                Assert.IsInstanceOfType(result.IsUp, typeof(bool));
            }
        }

        [TestMethod]
        public void TestPingNullOrEmpty()
        {
            List<string> hosts1 = new List<string> { };
            List<string> hosts2 = new List<string> { "" };
            List<string> hosts3 = new List<string> { "", "" };
            List<string> hosts4 = new List<string> { "123", "a", "1.2.3", "300.1.1.1", "1921.121.1.1/28" };
            List<string> hosts5 = null;
            List<string> hosts6 = new List<string> { null };
            List<string> hosts7 = new List<string> { null, null, null, null, "127.0.0.1" };

            SharpSploitResultList<Network.PingResult> results1 = Network.Ping(hosts1);
            SharpSploitResultList<Network.PingResult> results2 = Network.Ping(hosts2);
            SharpSploitResultList<Network.PingResult> results3 = Network.Ping(hosts3);
            SharpSploitResultList<Network.PingResult> results4 = Network.Ping(hosts4);
            try
            {
                SharpSploitResultList<Network.PingResult> results5 = Network.Ping(hosts5);
                Assert.Fail();
            }
            catch (NullReferenceException)
            {
                
            }
            SharpSploitResultList<Network.PingResult> results6 = Network.Ping(hosts6);
            SharpSploitResultList<Network.PingResult> results7 = Network.Ping(hosts7);
            Assert.IsNotNull(results1);
            Assert.IsNotNull(results2);
            Assert.IsNotNull(results3);
            Assert.IsNotNull(results4);
            Assert.IsNotNull(results6);
            Assert.IsNotNull(results7);

            Assert.AreEqual(0, results1.Count);
            Assert.AreEqual(0, results2.Count);
            Assert.AreEqual(0, results3.Count);
            Assert.AreEqual(0, results4.Count);
            Assert.AreEqual(0, results6.Count);
            Assert.AreEqual(1, results7.Count);
            Assert.AreEqual("127.0.0.1", results7[0].ComputerName);
            Assert.IsTrue(results7[0].IsUp);
        }

        [TestMethod]
        public void TestPortScan()
        {
            List<int> ports = new List<int> { 80, 443, 445 };
            SharpSploitResultList<Network.PortScanResult> results = Network.PortScan("127.0.0.1", ports);
            Assert.IsNotNull(results);
            Assert.AreEqual(1, results.Count);
            Assert.AreEqual("127.0.0.1", results[0].ComputerName);
            Assert.AreEqual(445, results[0].Port);
            Assert.IsTrue(results[0].IsOpen);
        }

        [TestMethod]
        public void TestPortScanList()
        {
            List<string> hosts = new List<string> { "127.0.0.1", "8.8.8.8", "1.1.1.1", "google.com", "192.168.200.1" };
            List<int> ports = new List<int> { 80, 443, 445 };

            SharpSploitResultList<Network.PortScanResult> results = Network.PortScan(hosts, ports, true, 1000, 300);
            Assert.IsNotNull(results);
            Assert.AreEqual(4, results.Count);
            Assert.AreEqual(4, results.Where(R => R.IsOpen).Count());
            foreach (Network.PortScanResult result in results)
            {
                Assert.IsNotNull(result);
                Assert.IsInstanceOfType(result.ComputerName, typeof(string));
                Assert.AreNotEqual("", result.ComputerName);
                Assert.IsTrue(ports.Contains(result.Port));
            }
        }

        [TestMethod]
        public void TestPortScanCidrThreaded()
        {
            List<string> hosts = new List<string> { "127.0.0.1", "8.8.8.8/24" };
            List<int> ports = new List<int> { 80, 443, 445 };

            SharpSploitResultList<Network.PortScanResult> results1 = Network.PortScan(hosts, ports, true, 8000, 120);
            SharpSploitResultList<Network.PortScanResult> results2 = Network.PortScan(hosts, ports, true, 10000, 1);

            Assert.IsNotNull(results1);
            Assert.IsNotNull(results2);
            Assert.AreEqual(results1.Count, results2.Count);
            Assert.AreEqual(results1.Where(R => R.IsOpen).Count(), results2.Where(R => R.IsOpen).Count());
            Assert.AreEqual(String.Join(",", results1.Select(R => R.ComputerName).OrderBy(C => C).ToArray()), String.Join(",", results2.Select(R => R.ComputerName).OrderBy(C => C).ToArray()));
            results1.AddRange(results2);
            foreach (Network.PortScanResult result in results1)
            {
                Assert.IsNotNull(result);
                Assert.AreNotEqual(result.ComputerName, "");
                Assert.IsInstanceOfType(result.ComputerName, typeof(string));
                Assert.IsInstanceOfType(result.IsOpen, typeof(bool));
            }
        }

        [TestMethod]
        public void TestPortScanNullOrEmpty()
        {
            List<string> hosts1 = new List<string> { };
            List<string> hosts2 = new List<string> { "" };
            List<string> hosts3 = new List<string> { "", "" };
            List<string> hosts4 = new List<string> { "123", "a", "1.2.3", "300.1.1.1", "1921.121.1.1/28" };
            List<string> hosts5 = null;
            List<string> hosts6 = new List<string> { null };
            List<string> hosts7 = new List<string> { null, null, null, null, "127.0.0.1" };
            List<int> ports1 = new List<int> { };
            List<int> ports2 = new List<int> { 0 };
            List<int> ports3 = new List<int> { 0, 0 };
            List<int> ports4 = new List<int> { 12345678, -123, 0, 1, -1 };
            List<int> ports5 = null;
            List<int> ports6 = new List<int> { 0 };
            List<int> ports7 = new List<int> { 0, 0, 0, 0, 445 };

            SharpSploitResultList<Network.PortScanResult> results1 = Network.PortScan(hosts1, ports1);
            SharpSploitResultList<Network.PortScanResult> results2 = Network.PortScan(hosts2, ports2);
            SharpSploitResultList<Network.PortScanResult> results3 = Network.PortScan(hosts3, ports3);
            SharpSploitResultList<Network.PortScanResult> results4 = Network.PortScan(hosts4, ports4);
            try
            {
                SharpSploitResultList<Network.PortScanResult> results5 = Network.PortScan(hosts5, ports5);
                Assert.Fail();
            }
            catch (NullReferenceException)
            {

            }
            SharpSploitResultList<Network.PortScanResult> results6 = Network.PortScan(hosts6, ports6);
            SharpSploitResultList<Network.PortScanResult> results7 = Network.PortScan(hosts7, ports7);
            Assert.IsNotNull(results1);
            Assert.IsNotNull(results2);
            Assert.IsNotNull(results3);
            Assert.IsNotNull(results4);
            Assert.IsNotNull(results6);
            Assert.IsNotNull(results7);

            Assert.AreEqual(0, results1.Count);
            Assert.AreEqual(0, results2.Count);
            Assert.AreEqual(0, results3.Count);
            Assert.AreEqual(0, results4.Count);
            Assert.AreEqual(0, results6.Count);
            Assert.AreEqual(1, results7.Count);
            Assert.AreEqual("127.0.0.1", results7[0].ComputerName);
            Assert.IsTrue(results7[0].IsOpen);
        }
    }
}

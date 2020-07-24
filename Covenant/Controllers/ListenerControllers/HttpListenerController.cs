// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using Covenant.Core;
using Covenant.API.Models;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;

namespace Covenant.Controllers
{
    [AllowAnonymous]
    public class HttpListenerController : Controller
    {
        private readonly Covenant.Models.Listeners.HttpListenerContext _context;
        private readonly Covenant.Models.Listeners.InternalListener _internalListener;

		public HttpListenerController(Covenant.Models.Listeners.HttpListenerContext context, Covenant.Models.Listeners.InternalListener internalListener)
        {
            _context = context;
            _internalListener = internalListener;
        }

        private void SetHeaders()
        {
            foreach (HttpProfileHeader header in _context.HttpProfiles.First().HttpResponseHeaders)
            {
                HttpContext.Response.Headers[header.Name] = header.Value;
            }
        }

        [AllowAnonymous]
        public async Task<ActionResult<string>> Route()
        {
            string guid = "";
            try
            {
                this.SetHeaders();
                guid = GetGuid(HttpContext);
                if (HttpContext.Request.Method == "GET")
                {
                    string response = String.Format(_context.HttpProfiles.First().HttpGetResponse.Replace("{", "{{").Replace("}", "}}").Replace("{{DATA}}", "{0}").Replace("{{GUID}}", "{1}"), await _internalListener.Read(guid), guid);
                    return Ok(response);
		        }
		        else if (HttpContext.Request.Method == "POST")
                {
                    using StreamReader reader = new StreamReader(Request.Body, System.Text.Encoding.UTF8);
                    string body = await reader.ReadToEndAsync();
                    string ExtractedMessage = body.ParseExact(_context.HttpProfiles.First().HttpPostRequest.Replace("{", "{{").Replace("}", "}}").Replace("{{DATA}}", "{0}").Replace("{{GUID}}", "{1}")).FirstOrDefault();
                    string guidToRead = await _internalListener.Write(guid, ExtractedMessage);
                    string postRead = await _internalListener.Read(guidToRead);
                    string response = String.Format(_context.HttpProfiles.First().HttpPostResponse.Replace("{", "{{").Replace("}", "}}").Replace("{{DATA}}", "{0}").Replace("{{GUID}}", "{1}"), postRead, guid);
                    return Ok(response);
                }
		        else
		        {
                    return NotFound();
                }
            }
            catch (ControllerNotFoundException e)
            {
                string response = String.Format(_context.HttpProfiles.First().HttpGetResponse.Replace("{DATA}", "{0}").Replace("{GUID}", "{1}"), e.Message, guid);
                return NotFound(response);
            }
            catch (Exception e)
            {
                string response = String.Format(_context.HttpProfiles.First().HttpGetResponse.Replace("{DATA}", "{0}").Replace("{GUID}", "{1}"), e.Message, guid);
                return NotFound(response);
            }
        }

        private string GetGuid(HttpContext httpContext)
        {
            foreach (HttpProfileHeader header in _context.HttpProfiles.First().HttpRequestHeaders)
            {
                if (header.Name.Contains("{GUID}"))
                {
                    return Parse(httpContext.Request.Headers.First(H => H.Value == header.Value).Key, header.Name.Replace("{GUID}", "{0}"))[0];
                }
                if (header.Value.Contains("{GUID}"))
                {
                    return Parse(httpContext.Request.Headers[header.Name].First(), header.Value.Replace("{GUID}", "{0}"))[0];
                }
            }
            string url = _context.HttpProfiles.First().HttpUrls.FirstOrDefault(U => U.StartsWith(httpContext.Request.Path, StringComparison.CurrentCultureIgnoreCase));
            if (url != null && url.Contains("{GUID}"))
            {
                return Parse((httpContext.Request.Path + httpContext.Request.QueryString), url.Replace("{GUID}", "{0}"))[0];
            }
            return null;
        }

        private static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{");
            if (format.Contains("{0}")) { format = format.Replace("{0}", "(?'group0'.*)"); }
            if (format.Contains("{1}")) { format = format.Replace("{1}", "(?'group1'.*)"); }
            if (format.Contains("{2}")) { format = format.Replace("{2}", "(?'group2'.*)"); }
            if (format.Contains("{3}")) { format = format.Replace("{3}", "(?'group3'.*)"); }
            if (format.Contains("{4}")) { format = format.Replace("{4}", "(?'group4'.*)"); }
            if (format.Contains("{5}")) { format = format.Replace("{5}", "(?'group5'.*)"); }
            Match match = new Regex(format).Match(data);
            List<string> matches = new List<string>();
            if (match.Groups["group0"] != null) { matches.Add(match.Groups["group0"].Value); }
            if (match.Groups["group1"] != null) { matches.Add(match.Groups["group1"].Value); }
            if (match.Groups["group2"] != null) { matches.Add(match.Groups["group2"].Value); }
            if (match.Groups["group3"] != null) { matches.Add(match.Groups["group3"].Value); }
            if (match.Groups["group4"] != null) { matches.Add(match.Groups["group4"].Value); }
            if (match.Groups["group5"] != null) { matches.Add(match.Groups["group5"].Value); }
            return matches;
        }
    }
}

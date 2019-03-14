// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Models;
using Covenant.Models.Grunts;
using Covenant.Models.Launchers;
using Covenant.Models.Covenant;

namespace Covenant.Controllers
{
    [Authorize]
	[ApiController]
    [Route("api/grunts/{id}/taskings")]
    public class GruntTaskingController : Controller
    {
        private readonly CovenantContext _context;

        public GruntTaskingController(CovenantContext context)
        {
            _context = context;
        }

        // GET: api/grunts/{id}/taskings
        // <summary>
        // Get GruntTaskings
        // </summary>
        [HttpGet(Name = "GetGruntTaskings")]
        public IEnumerable<GruntTasking> GetGruntTaskings(int id)
        {
            return _context.GruntTaskings.Where(GT => GT.GruntId == id).ToList();
        }

        // GET api/grunts/{id}/taskings/{task_name}
        // <summary>
        // Get a GruntTasking
        // </summary>
        [HttpGet("{taskname}", Name = "GetGruntTasking")]
        public ActionResult<GruntTasking> GetGruntTasking(int id, string taskname)
        {
            GruntTasking gruntTasking = _context.GruntTaskings.FirstOrDefault(GT => GT.GruntId == id && GT.Name == taskname);
            if (gruntTasking == null)
            {
                return NotFound();
            }
            return Ok(gruntTasking);
        }

        // POST api/grunts/{id}/taskings
        // <summary>
        // Create a GruntTasking
        // </summary>
        [HttpPost(Name = "CreateGruntTasking")]
        [ProducesResponseType(typeof(GruntTasking), 201)]
        public ActionResult<GruntTasking> CreateGruntTasking(int id, [FromBody] GruntTasking gruntTasking)
        {
            Models.Grunts.Grunt grunt = _context.Grunts.FirstOrDefault(G => G.Id == id);
            if (grunt == null)
            {
                return NotFound();
            }
            if (gruntTasking.type == GruntTasking.GruntTaskingType.Assembly)
            {
                GruntTask task = _context.GruntTasks.FirstOrDefault(T => T.Id == gruntTasking.TaskId);
                if (task == null)
                {
                    return NotFound();
                }
                task.Options = _context.GruntTaskOptions.Where(O => O.TaskId == task.Id).ToList();
                List<string> parameters = task.Options.OrderBy(O => O.OptionId).Select(O => O.Value).ToList();
                if (task.Name.ToLower() == "wmigrunt")
                {
                    Launcher l = _context.Launchers.FirstOrDefault(L => L.Name.ToLower() == parameters[1].ToLower());
                    if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                    {
                        return NotFound();
                    }
                    else
                    {
                        parameters[1] = l.LauncherString;
                    }
                }
                else if (task.Name.ToLower() == "dcomgrunt")
                {
                    Launcher l = _context.Launchers.FirstOrDefault(L => L.Name.ToLower() == parameters[1].ToLower());
                    if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                    {
                        return NotFound();
                    }
                    else
                    {
                        // Add .exe exetension if needed
                        List<string> split = l.LauncherString.Split(" ").ToList();
                        parameters[1] = split.FirstOrDefault();
                        if (!parameters[1].EndsWith(".exe")) { parameters[1] += ".exe"; }

                        // Add command parameters
                        split.RemoveAt(0);
                        parameters.Insert(2, String.Join(" ", split.ToArray()));
                        string Directory = "C:\\WINDOWS\\System32\\";
                        if (parameters[1].ToLower() == "powershell.exe") { Directory += "WindowsPowerShell\\v1.0\\"; }
                        else if (parameters[1].ToLower() == "wmic.exe") { Directory += "wbem\\"; }

                        parameters.Insert(3, Directory);
                    }
                }
                else if (task.Name.ToLower() == "dcomcommand")
                {
                    // Add .exe exetension if needed
                    List<string> split = parameters[1].Split(" ").ToList();
                    parameters[1] = split[0];
                    if (!parameters[1].EndsWith(".exe")) { parameters[1] += ".exe"; }

                    // Add command parameters
                    split.RemoveAt(0);
                    parameters.Insert(2, String.Join(" ", split.ToArray()));
                    string Directory = "C:\\WINDOWS\\System32\\";
                    if (parameters[1].ToLower() == "powershell.exe") { Directory += "WindowsPowerShell\\v1.0\\"; }
                    else if (parameters[1].ToLower() == "wmic.exe") { Directory += "wbem\\"; }

                    parameters.Insert(3, Directory);
                }
                else if (task.Name.ToLower() == "bypassuacgrunt")
                {
                    Launcher l = _context.Launchers.FirstOrDefault(L => L.Name.ToLower() == parameters[0].ToLower());
                    if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                    {
                        return NotFound();
                    }
                    else
                    {
                        // Add .exe exetension if needed
                        string[] split = l.LauncherString.Split(" ");
                        if (!parameters[0].EndsWith(".exe")) { parameters[0] += ".exe"; }

                        // Add parameters need for BypassUAC Task
                        string ArgParams = String.Join(" ", split.ToList().GetRange(1, split.Count() - 1));
                        string Directory = "C:\\WINDOWS\\System32\\";
                        if (parameters[0].ToLower() == "powershell.exe") { Directory += "WindowsPowerShell\\v1.0\\"; }
                        else if (parameters[0].ToLower() == "wmic.exe") { Directory += "wbem\\"; }

                        parameters.Add(ArgParams);
                        parameters.Add(Directory);
                        parameters.Add("0");
                    }
                }
                else if (task.Name.ToLower() == "bypassuaccommand")
                {
                    // Add .exe exetension if needed
                    string[] split = parameters[0].Split(" ");
                    if (!parameters[0].EndsWith(".exe")) { parameters[0] += ".exe"; }

                    // Add parameters need for BypassUAC Task
                    string ArgParams = String.Join(" ", split.ToList().GetRange(1, split.Count() - 1));
                    string Directory = "C:\\WINDOWS\\System32\\";
                    if (parameters[0].ToLower() == "powershell.exe") { Directory += "WindowsPowerShell\\v1.0\\"; }
                    else if (parameters[0].ToLower() == "wmic.exe") { Directory += "wbem\\"; }

                    parameters.Add(ArgParams);
                    parameters.Add(Directory);
                    parameters.Add("0");
                }
                try
                {
                    gruntTasking.Compile(
                        task.Code, parameters,
                        task.GetReferenceAssemblies(),
                        task.GetReferenceSourceLibraries(),
                        task.GetEmbeddedResources(),
                        grunt.DotNetFrameworkVersion
                    );
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Task Compilation failed: " + e.Message + e.StackTrace);
                    return BadRequest("Task returned compilation errors:" + e.Message + e.StackTrace);
                }
            }
            _context.GruntTaskings.Add(gruntTasking);
            _context.SaveChanges();
            return CreatedAtRoute(nameof(GetGruntTasking), new { id = id, taskname = gruntTasking.Name }, gruntTasking);
        }

        // PUT api/grunts/{id}/taskings/{task_name}
        // <summary>
        // Edit a GruntTasking
        // </summary>
        [HttpPut("{taskname}", Name = "EditGruntTasking")]
        public ActionResult<GruntTasking> EditGruntTasking(int id, string taskname, [FromBody] GruntTasking gruntTasking)
        {
            GruntTasking updatingGruntTasking = _context.GruntTaskings.FirstOrDefault(GT => id == GT.GruntId && taskname == GT.Name);
            if (updatingGruntTasking == null)
            {
                return NotFound();
            }
            List<String> credTaskNames = new List<string> { "Mimikatz", "SamDump", "LogonPasswords", "DcSync", "Rubeus", "Kerberoast" };
            GruntTask gruntTask = _context.GruntTasks.FirstOrDefault(G => G.Id == gruntTasking.TaskId);
            if (credTaskNames.Contains(gruntTask.Name))
            {
                List<CapturedCredential> capturedCredentials = CapturedCredential.ParseCredentials(gruntTasking.GruntTaskOutput);
                foreach (CapturedCredential cred in capturedCredentials)
                {
                    if (!ContextContainsCredentials(cred))
                    {
                        _context.Credentials.Add(cred);
                        _context.SaveChanges();
                    }
                }
            }
            updatingGruntTasking.status = gruntTasking.status;
            updatingGruntTasking.GruntTaskOutput = gruntTasking.GruntTaskOutput;
            _context.GruntTaskings.Update(updatingGruntTasking);
            _context.SaveChanges();

            return Ok(updatingGruntTasking);
        }

        // DELETE api/grunts/{id}/taskings/{task_name}
        // <summary>
        // Delete a GruntTasking
        // </summary>
        [HttpDelete("{taskname}", Name = "DeleteGruntTasking")]
        [ProducesResponseType(204)]
        public ActionResult DeleteGruntTasking(int id, string taskname)
        {
            GruntTasking removingGruntTasking = _context.GruntTaskings.FirstOrDefault(GT => id == GT.GruntId && GT.Name == taskname);
            if (removingGruntTasking == null)
            {
                return NotFound();
            }

            _context.GruntTaskings.Remove(removingGruntTasking);
            _context.SaveChanges();

            return new NoContentResult();
        }

        private bool ContextContainsCredentials(CapturedCredential cred)
        {
            switch (cred.Type)
            {
                case CapturedCredential.CredentialType.Password:
                    CapturedPasswordCredential passcred = (CapturedPasswordCredential)cred;
                    return _context.Credentials.Where(C => C.Type == CapturedCredential.CredentialType.Password)
                                   .Select(C => (CapturedPasswordCredential)C)
                                   .FirstOrDefault(PC =>
                                       PC.Type == passcred.Type &&
                                       PC.Domain == passcred.Domain &&
                                       PC.Username == passcred.Username &&
                                       PC.Password == passcred.Password
                                   ) != null;
                case CapturedCredential.CredentialType.Hash:
                    CapturedHashCredential hashcred = (CapturedHashCredential)cred;
                    return _context.Credentials.Where(C => C.Type == CapturedCredential.CredentialType.Hash)
                                   .Select(C => (CapturedHashCredential)C)
                                   .FirstOrDefault(PC =>
                                       PC.Type == hashcred.Type &&
                                       PC.Domain == hashcred.Domain &&
                                       PC.Username == hashcred.Username &&
                                       PC.Hash == hashcred.Hash &&
                                       PC.HashCredentialType == hashcred.HashCredentialType
                                   ) != null;
                case CapturedCredential.CredentialType.Ticket:
                    CapturedTicketCredential ticketcred = (CapturedTicketCredential)cred;
                    return _context.Credentials.Where(C => C.Type == CapturedCredential.CredentialType.Ticket)
                                   .Select(C => (CapturedTicketCredential)C)
                                   .FirstOrDefault(PC =>
                                       PC.Type == ticketcred.Type &&
                                       PC.Domain == ticketcred.Domain &&
                                       PC.Username == ticketcred.Username &&
                                       PC.Ticket == ticketcred.Ticket &&
                                       PC.TicketCredentialType == ticketcred.TicketCredentialType
                                   ) != null;
                default:
                    return _context.Credentials.FirstOrDefault(P =>
                                       P.Type == cred.Type &&
                                       P.Domain == cred.Domain &&
                                       P.Username == cred.Username
                                   ) != null;
            }
        }
    }
}

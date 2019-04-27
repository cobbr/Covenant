// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

using Covenant.Models;
using Covenant.Models.Grunts;
using Covenant.Models.Covenant;
using Covenant.Models.Indicators;

namespace Covenant.Controllers
{
    [Authorize(Policy = "RequireJwtBearer")]
    [ApiController]
    [Route("api/grunts")]
    public class GruntApiController : Controller
    {
        private readonly CovenantContext _context;
        private readonly UserManager<CovenantUser> _userManager;

        public GruntApiController(CovenantContext context, UserManager<CovenantUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        // GET: api/grunts
        // <summary>
        // Get a list of Grunts
        // </summary>
        [HttpGet(Name = "GetGrunts")]
        public ActionResult<IEnumerable<Grunt>> GetGrunts()
        {
            return _context.Grunts.ToList();
        }

        // GET api/grunts/{id}
        // <summary>
        // Get a Grunt by id
        // </summary>
        [HttpGet("{id:int}", Name = "GetGrunt")]
        public ActionResult<Grunt> GetGrunt(int id)
        {
            var grunt = _context.Grunts.FirstOrDefault(g => g.Id == id);
            if (grunt == null)
            {
                return NotFound($"NotFound - Grunt with id: {id}");
            }
            return grunt;
        }

        // GET: api/grunts/{name}
        // <summary>
        // Get a Grunt by name
        // </summary>
        [HttpGet("{name}", Name = "GetGruntByName")]
        public ActionResult<Grunt> GetGruntByName(string name)
        {
            var grunt = _context.Grunts.FirstOrDefault(g => g.Name == name);
            if (grunt == null)
            {
                return NotFound($"NotFound - Grunt with name: {name}");
            }
            return grunt;
        }

        // GET api/grunts/guid/{guid}
        // <summary>
        // Get a Grunt by GUID
        // </summary>
        [HttpGet("guid/{guid}", Name = "GetGruntByGUID")]
        public ActionResult<Grunt> GetGruntByGUID(string guid)
        {
            var grunt = _context.Grunts.FirstOrDefault(g => g.GUID == guid);
            if (grunt == null)
            {
                return NotFound($"NotFound - Grunt with GUID: {guid}");
            }
            return grunt;
        }

        // GET api/grunts/{id}/path/{tid}
        // <summary>
        // Get a path to a child Grunt by id
        // </summary>
        [HttpGet("{id}/path/{tid}", Name = "GetPathToChildGrunt")]
        public ActionResult<List<string>> GetPathToChildGrunt(int id, int tid)
        {
            var grunt = _context.Grunts.FirstOrDefault(g => g.Id == id);
            if (grunt == null)
            {
                return NotFound($"NotFound - Grunt with id: {id}");
            }
            List<string> path = new List<string>();
            bool found = GetPathToChildGrunt(id, tid, ref path);
            if (!found)
            {
                return NotFound($"NotFound - Path from Grunt with id: {id} to Grunt with id: {tid}");
            }
            path.Add(grunt.GUID);
            path.Reverse();
            return path;
        }

        // POST api/grunts
        // <summary>
        // Create a Grunt
        // </summary>
        [HttpPost(Name = "CreateGrunt")]
        [ProducesResponseType(typeof(Grunt), 201)]
        public ActionResult<Grunt> CreateGrunt([FromBody]Grunt grunt)
        {
            TargetIndicator indicator = _context.Indicators.Where(I => I.Name == "TargetIndicator")
                .Select(T => (TargetIndicator)T)
                .FirstOrDefault(T => T.ComputerName == grunt.Hostname && T.UserName == grunt.UserDomainName + "\\" + grunt.UserName);
            if (indicator == null && !string.IsNullOrWhiteSpace(grunt.Hostname))
            {
                _context.Indicators.Add(new TargetIndicator
                {
                    ComputerName = grunt.Hostname,
                    UserName = grunt.UserName,
                });
            }
            _context.Grunts.Add(grunt);
            _context.SaveChanges();
            return CreatedAtRoute(nameof(GetGrunt), new { id = grunt.Id }, grunt);
        }

        // PUT api/grunts
        // <summary>
        // Edit a Grunt
        // </summary>
        [HttpPut(Name = "EditGrunt")]
        public ActionResult<Grunt> EditGrunt([FromBody] Grunt grunt)
        {
            var matching_grunt = _context.Grunts.FirstOrDefault(g => grunt.Id == g.Id);
            if (matching_grunt == null)
            {
                return NotFound($"NotFound - Grunt with id: {grunt.Id}");
            }

            if (matching_grunt.Status != Grunt.GruntStatus.Active && grunt.Status == Grunt.GruntStatus.Active)
            {
                grunt.ActivationTime = DateTime.UtcNow;
                _context.Events.Add(new Event
                {
                    Time = DateTime.UtcNow,
                    MessageHeader = "[" + grunt.ActivationTime + " UTC] Grunt: " + grunt.Name + " from: " + grunt.Hostname + " has been activated!",
                    Level = Event.EventLevel.Highlight,
                    Context = "*"
                });
            }
            matching_grunt.Name = grunt.Name;
            matching_grunt.GUID = grunt.GUID;
            matching_grunt.OriginalServerGuid = grunt.OriginalServerGuid;
            matching_grunt.UserDomainName = grunt.UserDomainName;
            matching_grunt.UserName = grunt.UserName;
            matching_grunt.Status = grunt.Status;
            matching_grunt.Integrity = grunt.Integrity;
            matching_grunt.Process = grunt.Process;
            matching_grunt.LastCheckIn = grunt.LastCheckIn;
            matching_grunt.ActivationTime = grunt.ActivationTime;
            matching_grunt.IPAddress = grunt.IPAddress;
            matching_grunt.Hostname = grunt.Hostname;
            matching_grunt.OperatingSystem = grunt.OperatingSystem;

            matching_grunt.Children = grunt.Children;
            matching_grunt.CommType = grunt.CommType;
            matching_grunt.ValidateCert = grunt.ValidateCert;
            matching_grunt.UseCertPinning = grunt.UseCertPinning;
            matching_grunt.SMBPipeName = grunt.SMBPipeName;

            matching_grunt.ConnectAttempts = grunt.ConnectAttempts;
            matching_grunt.Delay = grunt.Delay;
            matching_grunt.JitterPercent = grunt.JitterPercent;
            matching_grunt.KillDate = grunt.KillDate;

            matching_grunt.CovenantIPAddress = grunt.CovenantIPAddress;
            matching_grunt.DotNetFrameworkVersion = grunt.DotNetFrameworkVersion;

            matching_grunt.GruntChallenge = grunt.GruntChallenge;
            matching_grunt.GruntNegotiatedSessionKey = grunt.GruntNegotiatedSessionKey;
            matching_grunt.GruntRSAPublicKey = grunt.GruntRSAPublicKey;
            matching_grunt.GruntSharedSecretPassword = grunt.GruntSharedSecretPassword;

            _context.Grunts.Update(matching_grunt);

            TargetIndicator indicator = _context.Indicators.Where(I => I.Name == "TargetIndicator")
                .Select(T => (TargetIndicator)T)
                .FirstOrDefault(T => T.ComputerName == grunt.Hostname && T.UserName == grunt.UserDomainName + "\\" + grunt.UserName);

            if (indicator == null && !string.IsNullOrWhiteSpace(grunt.Hostname))
            {
                _context.Indicators.Add(new TargetIndicator
                {
                    ComputerName = grunt.Hostname,
                    UserName = grunt.UserDomainName + "\\" + grunt.UserName
                });
            }
            _context.SaveChanges();

            return matching_grunt;
        }

        // DELETE api/grunts/{id}
        // <summary>
        // Delete a Grunt
        // </summary>
        [HttpDelete("{id}", Name = "DeleteGrunt")]
        [ProducesResponseType(204)]
        public ActionResult DeleteGrunt(int id)
        {
            var grunt = _context.Grunts.FirstOrDefault(g => g.Id == id);
            if (grunt == null)
            {
                return NotFound($"NotFound - Grunt with id: {id}");
            }

            _context.Grunts.Remove(grunt);
            _context.SaveChanges();
            return new NoContentResult();
        }

        private bool GetPathToChildGrunt(int ParentId, int ChildId, ref List<string> GruntPath)
        {
            if (ParentId == ChildId)
            {
                return true;
            }

            Grunt parentGrunt = _context.Grunts.FirstOrDefault(G => G.Id == ParentId);
            Grunt childGrunt = _context.Grunts.FirstOrDefault(G => G.Id == ChildId);
            if (parentGrunt == null || childGrunt == null)
            {
                return false;
            }
            if (parentGrunt.Children.Contains(childGrunt.GUID))
            {
                GruntPath.Add(childGrunt.GUID);
                return true;
            }
            foreach (string child in parentGrunt.Children)
            {
                Grunt directChild = _context.Grunts.FirstOrDefault(G => G.GUID == child);
                if (directChild == null)
                {
                    return false;
                }
                if (GetPathToChildGrunt(directChild.Id, ChildId, ref GruntPath))
                {
                    GruntPath.Add(directChild.GUID);
                    return true;
                }
            }
            return false;
        }
    }
}

// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

using Covenant.Hubs;
using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Grunts;
using Covenant.Models.Covenant;

namespace Covenant.Controllers
{
    [Authorize(Policy = "RequireJwtBearer")]
    [ApiController]
    [Route("api/grunts")]
    public class GruntApiController : Controller
    {
        private readonly CovenantContext _context;
        private readonly UserManager<CovenantUser> _userManager;
        private readonly IHubContext<GruntHub> _grunthub;

        public GruntApiController(CovenantContext context, UserManager<CovenantUser> userManager, IHubContext<GruntHub> grunthub)
        {
            _context = context;
            _userManager = userManager;
            _grunthub = grunthub;
        }

        // GET: api/grunts
        // <summary>
        // Get a list of Grunts
        // </summary>
        [HttpGet(Name = "GetGrunts")]
        public ActionResult<IEnumerable<Grunt>> GetGrunts()
        {
            return _context.Grunts;
        }

        // GET api/grunts/{id}
        // <summary>
        // Get a Grunt by id
        // </summary>
        [HttpGet("{id:int}", Name = "GetGrunt")]
        public async Task<ActionResult<Grunt>> GetGrunt(int id)
        {
            try
            {
                return await _context.GetGrunt(id);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // GET: api/grunts/{name}
        // <summary>
        // Get a Grunt by name
        // </summary>
        [HttpGet("{name}", Name = "GetGruntByName")]
        public async Task<ActionResult<Grunt>> GetGruntByName(string name)
        {
            try
            {
                return await _context.GetGruntByName(name);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // GET api/grunts/guid/{guid}
        // <summary>
        // Get a Grunt by GUID
        // </summary>
        [HttpGet("guid/{guid}", Name = "GetGruntByGUID")]
        public async Task<ActionResult<Grunt>> GetGruntByGUID(string guid)
        {
            try
            {
                return await _context.GetGruntByGUID(guid);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // GET api/grunts/originalguid/{serverguid}
        // <summary>
        // Get a Grunt by OriginalServerGUID
        // </summary>
        [HttpGet("originalguid/{serverguid}", Name = "GetGruntByOriginalServerGUID")]
        public async Task<ActionResult<Grunt>> GetGruntByOriginalServerGUID(string serverguid)
        {
            try
            {
                return await _context.GetGruntByOriginalServerGUID(serverguid);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // GET api/grunts/cookiekey/{cookie}
        // <summary>
        // Get a Grunt by CookieAuthKey
        // </summary>
        [HttpGet("cookiekey/{cookie}", Name = "GetGruntByCookieAuthKey")]
        public async Task<ActionResult<Grunt>> GetGruntByCookieAuthKey(string cookie)
        {
            try
            {
                return await _context.GetGruntByCookieAuthKey(System.Net.WebUtility.UrlDecode(cookie));
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // GET api/grunts/{id}/path/{cid}
        // <summary>
        // Get a path to a child Grunt by id
        // </summary>
        [HttpGet("{id}/path/{cid}", Name = "GetPathToChildGrunt")]
        public async Task<ActionResult<List<string>>> GetPathToChildGrunt(int id, int cid)
        {
            try
            {
                return await _context.GetPathToChildGrunt(id, cid);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // POST api/grunts
        // <summary>
        // Create a Grunt
        // </summary>
        [HttpPost(Name = "CreateGrunt")]
        [ProducesResponseType(typeof(Grunt), 201)]
        public async Task<ActionResult<Grunt>> CreateGrunt([FromBody]Grunt grunt)
        {
            try
            {
                Grunt createdGrunt = await _context.CreateGrunt(grunt);
                return CreatedAtRoute(nameof(GetGrunt), new { id = createdGrunt.Id }, createdGrunt);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // PUT api/grunts
        // <summary>
        // Edit a Grunt
        // </summary>
        [HttpPut(Name = "EditGrunt")]
        public async Task<ActionResult<Grunt>> EditGrunt([FromBody] Grunt grunt)
        {
            try
            {
                return await _context.EditGrunt(grunt, _userManager, HttpContext.User, _grunthub);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }

        // DELETE api/grunts/{id}
        // <summary>
        // Delete a Grunt
        // </summary>
        [HttpDelete("{id}", Name = "DeleteGrunt")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteGrunt(int id)
        {
            try
            {
                await _context.DeleteGrunt(id);
                return new NoContentResult();
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
        }
    }
}

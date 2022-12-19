// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models.Grunts;
using Covenant.Models.Covenant;

namespace Covenant.Controllers
{
    [ApiController, Route("api/grunts"), Authorize(Policy = "RequireJwtBearer")]
    public class GruntApiController : Controller
    {
        private readonly ICovenantService _service;

        public GruntApiController(ICovenantService service)
        {
            _service = service;
        }

        // GET: api/grunts
        // <summary>
        // Get a list of Grunts
        // </summary>
        [HttpGet(Name = "GetGrunts")]
        public async Task<ActionResult<IEnumerable<Grunt>>> GetGrunts()
        {
            return Ok(await _service.GetGrunts());
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
                return await _service.GetGrunt(id);
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
                return await _service.GetGruntByName(name);
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
                return await _service.GetGruntByGUID(guid);
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
                return await _service.GetGruntByOriginalServerGUID(serverguid);
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
                return await _service.GetPathToChildGrunt(id, cid);
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

        // GET api/grunts/{id}/outbound
        // <summary>
        // Get the outbound Grunt for a Grunt in the graph
        // </summary>
        [HttpGet("{id}/outbound", Name = "GetOutboundGrunt")]
        public async Task<ActionResult<Grunt>> GetOutboundGrunt(int id)
		{
			try
			{
				return await _service.GetOutboundGrunt(id);
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
                Grunt createdGrunt = await _service.CreateGrunt(grunt);
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
                return await _service.EditGrunt(grunt, await _service.GetCurrentUser(HttpContext.User));
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
                await _service.DeleteGrunt(id);
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

        // POST api/grunts/{id}/interact
        // <summary>
        // Interact with a Grunt
        // </summary>
        [HttpPost("{id}/interact", Name = "InteractGrunt")]
        [ProducesResponseType(typeof(GruntCommand), 201)]
        public async Task<ActionResult<GruntCommand>> InteractGrunt(int id, [FromBody] string command)
        {
            try
            {
                CovenantUser user = await _service.GetCurrentUser(this.HttpContext.User);
                GruntCommand gruntCommand = await _service.InteractGrunt(id, user.Id, command);
                return CreatedAtRoute("GetGruntCommand", new { id = gruntCommand.Id }, gruntCommand);
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

        // GET api/grunts/{id}/compileexecutor
        // <summary>
        // Compile an ImplantTemplate for a given Grunt
        // </summary>
        [HttpGet("{id}/compileexecutor", Name = "CompileGruntExecutor")]
        public async Task<ActionResult<byte[]>> CompileGruntExecutor(int id)
        {
            try
            {
                return await _service.CompileGruntExecutorCode(id, Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary, false);
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

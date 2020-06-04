// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models.Grunts;

namespace Covenant.Controllers
{
    [ApiController, Route("api/commands"), Authorize(Policy = "RequireJwtBearer")]
    public class GruntCommandApiController : Controller
    {
        private readonly ICovenantService _service;

        public GruntCommandApiController(ICovenantService service)
        {
            _service = service;
        }

        // GET: api/commands
        // <summary>
        // Get GruntCommands
        // </summary>
        [HttpGet(Name = "GetGruntCommands")]
        public async Task<ActionResult<IEnumerable<GruntCommand>>> GetGruntCommands()
        {
            return Ok(await _service.GetGruntCommands());
        }

        // GET: api/commands/{id}
        // <summary>
        // Get a GruntCommand
        // </summary>
        [HttpGet("{id}", Name = "GetGruntCommand")]
        public async Task<ActionResult<GruntCommand>> GetGruntCommand(int id)
        {
            try
            {
                return await _service.GetGruntCommand(id);
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

        // POST api/commands
        // <summary>
        // Create a GruntCommand
        // </summary>
        [HttpPost(Name = "CreateGruntCommand"), ProducesResponseType(typeof(GruntCommand), 201)]
        public async Task<ActionResult<GruntCommand>> CreateGruntCommand([FromBody] GruntCommand gruntCommand)
        {
            try
            {
                gruntCommand.Grunt = await _service.GetGrunt(gruntCommand.GruntId);
                GruntCommand createdCommand = await _service.CreateGruntCommand(gruntCommand);
                return CreatedAtRoute(nameof(GetGruntCommand), new { id = createdCommand.Id }, createdCommand);
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

        // PUT api/commands
        // <summary>
        // Edit a GruntCommand
        // </summary>
        [HttpPut(Name = "EditGruntCommand")]
        public async Task<ActionResult<GruntCommand>> EditGruntCommand([FromBody] GruntCommand gruntCommand)
        {
            try
            {
                return await _service.EditGruntCommand(gruntCommand);
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

        // DELETE api/commands/{id}
        // <summary>
        // Delete a GruntTasking
        // </summary>
        [HttpDelete("{id}", Name = "DeleteGruntCommand")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteGruntCommand(int id)
        {
            try
            {
                await _service.DeleteGruntCommand(id);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            return new NoContentResult();
        }
    }
}

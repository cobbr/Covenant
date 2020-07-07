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
    [ApiController, Route("api/commandoutputs"), Authorize(Policy = "RequireJwtBearer")]
    public class CommandOutputApiController : Controller
    {
        private readonly ICovenantService _service;

        public CommandOutputApiController(ICovenantService service)
        {
            _service = service;
        }

        // GET: api/commandoutputs
        // <summary>
        // Get CommandOutputs
        // </summary>
        [HttpGet(Name = "GetCommandOutputs")]
        public async Task<ActionResult<IEnumerable<CommandOutput>>> GetCommandOutputs()
        {
            return Ok(await _service.GetCommandOutputs());
        }

        // GET: api/commandoutputs/{id}
        // <summary>
        // Get a CommandOutput
        // </summary>
        [HttpGet("{id}", Name = "GetCommandOutput")]
        public async Task<ActionResult<CommandOutput>> GetCommandOutput(int id)
        {
            try
            {
                return await _service.GetCommandOutput(id);
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

        // POST api/commandoutputs
        // <summary>
        // Create a CommandOutput
        // </summary>
        [HttpPost(Name = "CreateCommandOutput"), ProducesResponseType(typeof(CommandOutput), 201)]
        public async Task<ActionResult<CommandOutput>> CreateCommandOutput([FromBody] CommandOutput CommandOutput)
        {
            try
            {
                CommandOutput createdCommandOutput = await _service.CreateCommandOutput(CommandOutput);
                return CreatedAtRoute(nameof(GetCommandOutput), new { id = createdCommandOutput.Id }, createdCommandOutput);
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

        // PUT api/commandoutputs
        // <summary>
        // Edit a CommandOutput
        // </summary>
        [HttpPut(Name = "EditCommandOutput")]
        public async Task<ActionResult<CommandOutput>> EditCommandOutput([FromBody] CommandOutput CommandOutput)
        {
            try
            {
                return await _service.EditCommandOutput(CommandOutput);
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

        // PUT api/commandoutputs/append/{id}
        // <summary>
        // Append to a CommandOutput
        // </summary>
        [HttpPut("append/{id}", Name = "AppendCommandOutput")]
        public async Task<ActionResult> AppendCommandOutput(int id, [FromBody] string append)
        {
            try
            {
                CommandOutput output = await _service.GetCommandOutput(id);
                _service.DisposeContext();
                output.Output += append;
                await _service.EditCommandOutput(output);
                return Ok();
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

        // DELETE api/commandoutputs/{id}
        // <summary>
        // Delete a GruntTasking
        // </summary>
        [HttpDelete("{id}", Name = "DeleteCommandOutput")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteCommandOutput(int id)
        {
            try
            {
                await _service.DeleteCommandOutput(id);
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

// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Grunts;

namespace Covenant.Controllers
{
    [Authorize(Policy = "RequireJwtBearer")]
    [ApiController]
    [Route("api/grunttasks")]
    public class GruntTaskApiController : Controller
    {
        private readonly CovenantContext _context;

        public GruntTaskApiController(CovenantContext context)
        {
            _context = context;
        }

        // GET: api/grunttasks
        // <summary>
        // Get Tasks
        // </summary>
        [HttpGet(Name = "GetGruntTasks")]
        public async Task<ActionResult<IEnumerable<GruntTask>>> GetGruntTasks()
        {
            return Ok(await _context.GetGruntTasks());
        }

        // GET: api/grunttasks/{id}
        // <summary>
        // Get a Task by Id
        // </summary>
        [HttpGet("{id:int}", Name = "GetGruntTask")]
        public async Task<ActionResult<GruntTask>> GetGruntTask(int id)
        {
            try
            {
                return await _context.GetGruntTask(id);
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

        // GET: api/grunttasks/{taskname}
        // <summary>
        // Get a Task by Name
        // </summary>
        [HttpGet("{taskname}", Name = "GetGruntTaskByName")]
        public async Task<ActionResult<GruntTask>> GetGruntTaskByName(string taskname)
        {
            try
            {
                return await _context.GetGruntTaskByName(taskname);
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

        // POST api/grunttasks
        // <summary>
        // Create a Task
        // </summary>
        [HttpPost(Name = "CreateGruntTask")]
        [ProducesResponseType(typeof(GruntTask), 201)]
        public async Task<ActionResult<GruntTask>> CreateGruntTask([FromBody] GruntTask task)
        {
            GruntTask savedTask = await _context.CreateGruntTask(task);
            return CreatedAtRoute(nameof(GetGruntTask), new { id = savedTask.Id }, savedTask);
        }

        // PUT api/grunttasks
        // <summary>
        // Edit a Task
        // </summary>
        [HttpPut(Name = "EditGruntTask")]
        public async Task<ActionResult<GruntTask>> EditGruntTask([FromBody] GruntTask task)
        {
            try
            {
                return await _context.EditGruntTask(task);
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

        // DELETE api/grunttasks/{id}
        // <summary>
        // Delete a Task
        // </summary>
        [HttpDelete("{id}", Name = "DeleteGruntTask")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteGruntTask(int id)
        {
            try
            {
                await _context.DeleteGruntTask(id);
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

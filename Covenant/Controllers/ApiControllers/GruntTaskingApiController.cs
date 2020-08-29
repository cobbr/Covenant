// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models.Grunts;

namespace Covenant.Controllers
{
    [ApiController, Route("api"), Authorize(Policy = "RequireJwtBearer")]
    public class GruntTaskingApiController : Controller
    {
        private readonly ICovenantService _service;

        public GruntTaskingApiController(ICovenantService service)
        {
            _service = service;
        }

        // GET: api/taskings
        // <summary>
        // Get GruntTaskings
        // </summary>
        [HttpGet("taskings", Name = "GetAllGruntTaskings")]
        public async Task<ActionResult<IEnumerable<GruntTasking>>> GetAllGruntTaskings()
        {
            return Ok(await _service.GetGruntTaskings());
        }

        // GET: api/grunts/{id}/taskings
        // <summary>
        // Get GruntTaskings for Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings", Name = "GetGruntTaskings")]
        public async Task<ActionResult<IEnumerable<GruntTasking>>> GetGruntTaskings(int id)
        {
            return Ok(await _service.GetGruntTaskingsForGrunt(id));
        }

        // GET: api/grunts/{id}/taskings/search
        // <summary>
        // Get GruntTaskings for Grunt or any child Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings/search", Name = "GetSearchGruntTaskings")]
        public async Task<ActionResult<IEnumerable<GruntTasking>>> GetSearchGruntTaskings(int id)
        {
            return Ok(await _service.GetGruntTaskingsSearch(id));
        }

        // GET: api/grunts/{id}/taskings/uninitialized
        // <summary>
        // Get uninitialized GruntTaskings for Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings/uninitialized", Name = "GetUninitializedGruntTaskings")]
        public async Task<ActionResult<IEnumerable<GruntTasking>>> GetUninitializedGruntTaskings(int id)
        {
            return Ok(await _service.GetUninitializedGruntTaskingsForGrunt(id));
        }

        // GET: api/grunts/{id}/taskings/search/uninitialized
        // <summary>
        // Get uninitialized GruntTaskings for Grunt or any child Grunt
        // </summary>
        [HttpGet("grunts/{id}/taskings/search/uninitialized", Name = "GetSearchUninitializedGruntTaskings")]
        public async Task<ActionResult<IEnumerable<GruntTasking>>> GetSearchUninitializedGruntTaskings(int id)
        {
            IEnumerable<GruntTasking> taskings = await _service.GetGruntTaskingsSearch(id);
            return Ok(taskings
                .Where(GT => GT.Status == GruntTaskingStatus.Uninitialized)
                .ToList());
        }

        // GET api/taskings/{tid}
        // <summary>
        // Get a GruntTasking
        // </summary>
        [HttpGet("taskings/{tid:int}", Name = "GetGruntTasking")]
        public async Task<ActionResult<GruntTasking>> GetGruntTasking(int tid)
        {
            try
            {
                return await _service.GetGruntTasking(tid);
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

        // GET api/taskings/{taskingname}
        // <summary>
        // Get a GruntTasking
        // </summary>
        [HttpGet("grunts/taskings/{taskingname}", Name = "GetGruntTaskingByName")]
        public async Task<ActionResult<GruntTasking>> GetGruntTaskingByName(string taskingname)
        {
            try
            {
                return await _service.GetGruntTaskingByName(taskingname);
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

        // POST api/taskings
        // <summary>
        // Create a GruntTasking
        // </summary>
        [HttpPost("taskings", Name = "CreateGruntTasking")]
        [ProducesResponseType(typeof(GruntTasking), 201)]
        public async Task<ActionResult<GruntTasking>> CreateGruntTasking([FromBody] GruntTasking gruntTasking)
        {
            try
            {
                GruntTasking tasking = await _service.CreateGruntTasking(gruntTasking);
                return CreatedAtRoute(nameof(GetGruntTasking), new { tid = tasking.Id }, tasking);
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

        // PUT api/taskings
        // <summary>
        // Edit a GruntTasking
        // </summary>
        [HttpPut("taskings", Name = "EditGruntTasking")]
        public async Task<ActionResult<GruntTasking>> EditGruntTasking([FromBody] GruntTasking gruntTasking)
        {
            try
            {
                return await _service.EditGruntTasking(gruntTasking);
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

        // DELETE api/taskings/{tid}
        // <summary>
        // Delete a GruntTasking
        // </summary>
        [HttpDelete("taskings/{tid}", Name = "DeleteGruntTasking")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteGruntTasking(int tid)
        {
            try
            {
                await _service.DeleteGruntTasking(tid);
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

// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models.Indicators;

namespace Covenant.Controllers
{
    [ApiController, Route("api/indicators"), Authorize(Policy = "RequireJwtBearer")]
    public class IndicatorApiController : Controller
    {
        private readonly ICovenantService _service;

        public IndicatorApiController(ICovenantService service)
        {
            _service = service;
        }

        // GET: api/indicators/report
        // <summary>
        // Get a report of Indicators
        // </summary>
        [HttpGet("results", Name = "GetReport")]
        public ActionResult<string> GetReport()
        {
            // TODO
            return "";
        }

        // GET: api/indicators
        // <summary>
        // Get a list of Indicators
        // </summary>
        [HttpGet(Name = "GetIndicators")]
        public async Task<ActionResult<IEnumerable<Indicator>>> GetIndicators()
        {
            return Ok(await _service.GetIndicators());
        }

        // GET: api/indicators/files
        // <summary>
        // Get a list of FileIndicators
        // </summary>
        [HttpGet("files", Name = "GetFileIndicators")]
        public async Task<ActionResult<IEnumerable<FileIndicator>>> GetFileIndicators()
        {
            return Ok(await _service.GetFileIndicators());
        }

        // GET: api/indicators/networks
        // <summary>
        // Get a list of NetworksIndicators
        // </summary>
        [HttpGet("networks", Name = "GetNetworkIndicators")]
        public async Task<ActionResult<IEnumerable<NetworkIndicator>>> GetNetworkIndicators()
        {
            return Ok(await _service.GetNetworkIndicators());
        }

        // GET: api/indicators/targets
        // <summary>
        // Get a list of TargetIndicators
        // </summary>
        [HttpGet("targets", Name = "GetTargetIndicators")]
        public async Task<ActionResult<IEnumerable<TargetIndicator>>> GetTargetIndicators()
        {
            return Ok(await _service.GetTargetIndicators());
        }

        // GET api/indicators/{id}
        // <summary>
        // Get an Indicator by id
        // </summary>
        [HttpGet("{id}", Name = "GetIndicator")]
        public async Task<ActionResult<Indicator>> GetIndicator(int id)
        {
            try
            {
                return await _service.GetIndicator(id);
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

        // GET: api/indicators/files/{id}
        // <summary>
        // Get a list of FileIndicators
        // </summary>
        [HttpGet("files/{id}", Name = "GetFileIndicator")]
        public async Task<ActionResult<FileIndicator>> GetFileIndicator(int id)
        {
            try
            {
                return await _service.GetFileIndicator(id);
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

        // GET: api/indicators/networks/{id}
        // <summary>
        // Get a list of NetworksIndicators
        // </summary>
        [HttpGet("networks/{id}", Name = "GetNetworkIndicator")]
        public async Task<ActionResult<NetworkIndicator>> GetNetworkIndicator(int id)
        {
            try
            {
                return await _service.GetNetworkIndicator(id);
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

        // GET: api/indicators/targets/{id}
        // <summary>
        // Get a list of TargetIndicators
        // </summary>
        [HttpGet("targets/{id}", Name = "GetTargetIndicator")]
        public async Task<ActionResult<TargetIndicator>> GetTargetIndicator(int id)
        {
            try
            {
                return await _service.GetTargetIndicator(id);
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

        // POST api/indicators
        // <summary>
        // Create a Indicator
        // </summary>
        [HttpPost(Name = "CreateIndicator")]
        [ProducesResponseType(typeof(Indicator), 201)]
        public async Task<ActionResult<Indicator>> CreateIndicator([FromBody]Indicator indicator)
        {
            try
            {
                Indicator createdIndicator = await _service.CreateIndicator(indicator);
                return CreatedAtRoute(nameof(GetIndicator), new { id = createdIndicator.Id }, createdIndicator);
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

        // PUT api/indicators
        // <summary>
        // Edit a Indicator
        // </summary>
        [HttpPut(Name = "EditIndicator")]
        public async Task<ActionResult<Indicator>> EditIndicator([FromBody] Indicator indicator)
        {
            try
            {
                return await _service.EditIndicator(indicator);
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

        // DELETE api/indicators/{id}
        // <summary>
        // Delete a Indicator
        // </summary>
        [HttpDelete("{id}", Name = "DeleteIndicator")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteIndicator(int id)
        {
            try
            {
                await _service.DeleteIndicator(id);
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

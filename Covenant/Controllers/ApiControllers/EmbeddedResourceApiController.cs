// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Grunts;

namespace Covenant.Controllers.ApiControllers
{
    [ApiController, Route("api/embeddedresources"), Authorize(Policy = "RequireJwtBearer")]
    public class EmbeddedResourceApiController : Controller
    {
        private readonly ICovenantService _service;

        public EmbeddedResourceApiController(ICovenantService service)
        {
            _service = service;
        }

        // GET: api/embeddedresources
        [HttpGet(Name = "GetEmbeddedResources")]
        public async Task<ActionResult<IEnumerable<EmbeddedResource>>> GetEmbeddedResources()
        {
            return Ok(await _service.GetEmbeddedResources());
        }

        // GET api/embeddedresources/{id}
        [HttpGet("{id}", Name = "GetEmbeddedResource")]
        public async Task<ActionResult<EmbeddedResource>> GetEmbeddedResource(int id)
        {
            try
            {
                return await _service.GetEmbeddedResource(id);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }

        // POST api/embeddedresources
        [HttpPost(Name = "CreateEmbeddedResource")]
        public async Task<ActionResult<EmbeddedResource>> CreateEmbeddedResource([FromBody]EmbeddedResource resource)
        {
            try
            {
                EmbeddedResource createdResource = await _service.CreateEmbeddedResource(resource);
                return CreatedAtRoute(nameof(GetEmbeddedResource), new { id = createdResource.Id }, createdResource);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }

        // PUT api/embeddedresources
        [HttpPut(Name = "EditEmbeddedResource")]
        public async Task<ActionResult<EmbeddedResource>> EditEmbeddedResource([FromBody]EmbeddedResource resource)
        {
            try
            {
                return await _service.EditEmbeddedResource(resource);
            }
            catch (ControllerNotFoundException e)
            {
                return NotFound(e.Message);
            }
            catch (ControllerBadRequestException e)
            {
                return BadRequest(e.Message);
            }
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }

        // DELETE api/embeddedresources/{id}
        [HttpDelete("{id}", Name = "DeleteEmbeddedResource")]
        public async Task<ActionResult> DeleteEmbeddedResource(int id)
        {
            try
            {
                await _service.DeleteEmbeddedResource(id);
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
            catch (ControllerUnauthorizedException)
            {
                return new UnauthorizedResult();
            }
        }
    }
}

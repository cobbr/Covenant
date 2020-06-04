// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models.Listeners;

namespace Covenant.Controllers
{
    [ApiController, Route("api/listeners"), Authorize(Policy = "RequireJwtBearer")]
    public class ListenerApiController : Controller
    {
        private readonly ICovenantService _service;

        public ListenerApiController(ICovenantService service)
        {
            _service = service;
        }

        // GET: api/listeners/types
        // <summary>
        // Get listener types
        // </summary>
        [HttpGet("types", Name = "GetListenerTypes")]
        public async Task<ActionResult<IEnumerable<ListenerType>>> GetListenerTypes()
        {
            return Ok(await _service.GetListenerTypes());
        }

        // GET: api/listeners/types/{id}
        // <summary>
        // Get a listener type
        // </summary>
        [HttpGet("types/{id}", Name = "GetListenerType")]
        public async Task<ActionResult<ListenerType>> GetListenerType(int id)
        {
            try
            {
                return await _service.GetListenerType(id);
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

        // GET: api/listeners
        // <summary>
        // Get listeners
        // </summary>
        [HttpGet(Name = "GetListeners")]
        public async Task<ActionResult<IEnumerable<Listener>>> GetListeners()
        {
            return Ok(await _service.GetListeners());
        }

        // GET: api/listeners/{id}
        // <summary>
        // Get a listener
        // </summary>
        [HttpGet("{id}", Name = "GetListener")]
        public async Task<ActionResult<Listener>> GetListener(int id)
        {
            try
            {
                return await _service.GetListener(id);
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

        // PUT api/listeners
        // <summary>
        // Edit a Listener
        // </summary>
        [HttpPut(Name = "EditListener")]
        public async Task<ActionResult<Listener>> EditListener([FromBody] Listener listener)
        {
            try
            {
                return await _service.EditListener(listener);
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

        // DELETE api/listeners/{id}
        // <summary>
        // Delete a Listener
        // </summary>
        [HttpDelete("{id}", Name = "DeleteListener")]
        public async Task<ActionResult> DeleteListener(int id)
        {
            try
            {
                await _service.DeleteListener(id);
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

        // GET api/listeners/http/{id}
        // <summary>
        // Get an HttpListener
        // </summary>
        [HttpGet("http/{id}", Name = "GetHttpListener")]
        public async Task<ActionResult<HttpListener>> GetHttpListener(int id)
        {
            try
            {
                return await _service.GetHttpListener(id);
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

        // POST api/listeners/http
        // <summary>
        // Create an HttpListener
        // </summary>
        [HttpPost("http", Name = "CreateHttpListener")]
        public async Task<ActionResult<HttpListener>> CreateHttpListener([FromBody] HttpListener listener)
        {
            try
            {
                return await _service.CreateHttpListener(listener);
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

        // PUT api/listeners/http
        // <summary>
        // Edit HttpListener
        // </summary>
        [HttpPut("http", Name = "EditHttpListener")]
        public async Task<ActionResult<HttpListener>> EditHttpListener([FromBody] HttpListener listener)
        {
            try
            {
                return await _service.EditHttpListener(listener);
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

        // GET api/listeners/bridge/{id}
        // <summary>
        // Get a BridgeListener
        // </summary>
        [HttpGet("bridge/{id}", Name = "GetBridgeListener")]
        public async Task<ActionResult<BridgeListener>> GetBridgeListener(int id)
        {
            try
            {
                return await _service.GetBridgeListener(id);
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

        // POST api/listeners/bridge
        // <summary>
        // Create a BridgeListener
        // </summary>
        [HttpPost("bridge", Name = "CreateBridgeListener")]
        public async Task<ActionResult<BridgeListener>> CreateBridgeListener([FromBody] BridgeListener listener)
        {
            try
            {
                return await _service.CreateBridgeListener(listener);
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

        // PUT api/listeners/bridge
        // <summary>
        // Edit BridgeListener
        // </summary>
        [HttpPut("bridge", Name = "EditBridgeListener")]
        public async Task<ActionResult<BridgeListener>> EditBridgeListener([FromBody] BridgeListener listener)
        {
            try
            {
                return await _service.EditBridgeListener(listener);
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

        // GET api/listeners/{id}/hostedfiles
        // <summary>
        // Get HostedFiles
        // </summary>
        [HttpGet("{id}/hostedfiles", Name = "GetHostedFiles")]
        public async Task<ActionResult<IEnumerable<HostedFile>>> GetHostedFiles(int id)
        {
            return Ok(await _service.GetHostedFilesForListener(id));
        }

        // GET api/listeners/{id}/hostedfiles/{hfid}
        // <summary>
        // Get a HostedFile
        // </summary>
        [HttpGet("{id}/hostedfiles/{hfid}", Name = "GetHostedFile")]
        public async Task<ActionResult<HostedFile>> GetHostedFile(int id, int hfid)
        {
            try
            {
                return await _service.GetHostedFileForListener(id, hfid);
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

        // POST api/listeners/{id}/hostedfiles
        // <summary>
        // Create a HostedFile
        // </summary>
        [HttpPost("{id}/hostedfiles", Name = "CreateHostedFile")]
        [ProducesResponseType(typeof(HostedFile), 201)]
        public async Task<ActionResult<HostedFile>> CreateHostedFile(int id, [FromBody] HostedFile file)
        {
            try
            {
                HostedFile hostedFile = await _service.CreateHostedFile(file);
                return CreatedAtRoute(nameof(GetHostedFile), new { id = id, hfid = file.Id }, hostedFile);
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

        // PUT api/listeners/{id}/hostedfiles
        // <summary>
        // Edit HostedFile
        // </summary>
        [HttpPut("{id}/hostedfiles", Name = "EditHostedFile")]
        public async Task<ActionResult<HostedFile>> EditHostedFile(int id, [FromBody] HostedFile file)
        {
            try
            {
                return await _service.EditHostedFile(id, file);
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

        // DELETE api/listeners/{id}/hostedfiles/{hfid}
        // <summary>
        // Delete a HostedFile
        // </summary>
        [HttpDelete("{id}/hostedfiles/{hfid}", Name = "DeleteHostedFile")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteHostedFile(int id, int hfid)
        {
            try
            {
                await this.DeleteHostedFile(id, hfid);
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

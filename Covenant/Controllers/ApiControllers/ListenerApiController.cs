// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Configuration;

using Covenant.Core;
using Covenant.Hubs;
using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Models.Listeners;

namespace Covenant.Controllers
{
    [Authorize(Policy = "RequireJwtBearer")]
    [ApiController]
    [Route("api/listeners")]
    public class ListenerApiController : Controller
    {
        private readonly CovenantContext _context;
        private readonly UserManager<CovenantUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ConcurrentDictionary<int, CancellationTokenSource> _ListenerCancellationTokens;
        private readonly IHubContext<EventHub> _eventhub;

        public ListenerApiController(CovenantContext context, UserManager<CovenantUser> userManager, IConfiguration configuration, ConcurrentDictionary<int, CancellationTokenSource> ListenerCancellationTokens, IHubContext<EventHub> eventhub)
        {
            _context = context;
            _userManager = userManager;
            _configuration = configuration;
            _ListenerCancellationTokens = ListenerCancellationTokens;
            _eventhub = eventhub;
        }

        // GET: api/listeners/types
        // <summary>
        // Get listener types
        // </summary>
        [HttpGet("types", Name = "GetListenerTypes")]
        public async Task<ActionResult<IEnumerable<ListenerType>>> GetListenerTypes()
        {
            return Ok(await _context.GetListenerTypes());
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
                return await _context.GetListenerType(id);
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
            return Ok(await _context.GetListeners());
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
                return await _context.GetListener(id);
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
                return await _context.EditListener(listener, _ListenerCancellationTokens, _eventhub);
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
                await _context.DeleteListener(id, _ListenerCancellationTokens);
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
        // Get an  HttpListener
        // </summary>
        [HttpGet("http/{id}", Name = "GetActiveHttpListener")]
        public async Task<ActionResult<HttpListener>> GetHttpListener(int id)
        {
            try
            {
                return await _context.GetHttpListener(id);
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
                return await _context.CreateHttpListener(_userManager, _configuration, listener, _ListenerCancellationTokens, _eventhub);
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
                return await _context.EditHttpListener(listener, _ListenerCancellationTokens, _eventhub);
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
        [Authorize]
        [HttpGet("{id}/hostedfiles", Name = "GetHostedFiles")]
        public async Task<ActionResult<IEnumerable<HostedFile>>> GetHostedFiles(int id)
        {
            return Ok(await _context.GetHostedFiles(id));
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
                return await _context.GetHostedFile(id, hfid);
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
                HostedFile hostedFile = await _context.CreateHostedFile(file);
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
                return await _context.EditHostedFile(id, file);
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

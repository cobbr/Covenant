// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;

namespace Covenant.Controllers
{
    [ApiController, Route("api/credentials"), Authorize(Policy = "RequireJwtBearer")]
    public class CredentialApiController : Controller
    {
        private readonly ICovenantService _service;

        public CredentialApiController(ICovenantService service)
        {
            _service = service;
        }

        // GET: api/credentials
        // <summary>
        // Get a list of CapturedCredentials
        // </summary>
        [HttpGet(Name = "GetCredentials")]
        public async Task<ActionResult<IEnumerable<CapturedCredential>>> GetCredentials()
        {
            return Ok(await _service.GetCredentials());
        }

        // GET: api/credentials/passwords
        // <summary>
        // Get a list of CapturedPasswordCredentials
        // </summary>
        [HttpGet("passwords", Name = "GetPasswordCredentials")]
        public async Task<ActionResult<IEnumerable<CapturedPasswordCredential>>> GetPasswordCredentials()
        {
            return Ok(await _service.GetPasswordCredentials());
        }

        // GET: api/credentials/hashes
        // <summary>
        // Get a list of CapturedHashCredentials
        // </summary>
        [HttpGet("hashes", Name = "GetHashCredentials")]
        public async Task<ActionResult<IEnumerable<CapturedHashCredential>>> GetHashCredentials()
        {
            return Ok(await _service.GetHashCredentials());
        }

        // GET: api/credentials/tickets
        // <summary>
        // Get a list of CapturedTicketCredentials
        // </summary>
        [HttpGet("tickets", Name = "GetTicketCredentials")]
        public async Task<ActionResult<IEnumerable<CapturedTicketCredential>>> GetTicketCredentials()
        {
            return Ok(await _service.GetTicketCredentials());
        }

        // GET api/credentials/{id}
        // <summary>
        // Get a CapturedCredential by id
        // </summary>
        [HttpGet("{id}", Name = "GetCredential")]
        public async Task<ActionResult<CapturedCredential>> GetCredential(int id)
        {
            try
            {
                return await _service.GetCredential(id);
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

        // GET api/credentials/passwords/{id}
        // <summary>
        // Get a CapturedPasswordCredential by id
        // </summary>
        [HttpGet("passwords/{id}", Name = "GetPasswordCredential")]
        public async Task<ActionResult<CapturedPasswordCredential>> GetPasswordCredential(int id)
        {
            try
            {
                return await _service.GetPasswordCredential(id);
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

        // GET api/credentials/hashes/{id}
        // <summary>
        // Get a CapturedHashCredential by id
        // </summary>
        [HttpGet("hashes/{id}", Name = "GetHashCredential")]
        public async Task<ActionResult<CapturedHashCredential>> GetHashCredential(int id)
        {
            try
            {
                return await _service.GetHashCredential(id);
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

        // GET api/credentials/tickets/{id}
        // <summary>
        // Get a CapturedTicketCredential by id
        // </summary>
        [HttpGet("tickets/{id}", Name = "GetTicketCredential")]
        public async Task<ActionResult<CapturedTicketCredential>> GetTicketCredential(int id)
        {
            try
            {
                return await _service.GetTicketCredential(id);
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

        // POST api/credentials/passwords
        // <summary>
        // Create a CapturedPasswordCredential
        // </summary>
        [HttpPost("passwords", Name = "CreatePasswordCredential")]
        [ProducesResponseType(typeof(CapturedPasswordCredential), 201)]
        public async Task<ActionResult<CapturedPasswordCredential>> CreatePasswordCredential([FromBody]CapturedPasswordCredential credential)
        {
            try
            {
                CapturedPasswordCredential addedCredential = await _service.CreatePasswordCredential(credential);
                return CreatedAtRoute(nameof(GetPasswordCredential), new { id = addedCredential.Id }, addedCredential);
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

        // POST api/credentials/hashes
        // <summary>
        // Create a CapturedHashCredential
        // </summary>
        [HttpPost("hashes", Name = "CreateHashCredential")]
        [ProducesResponseType(typeof(CapturedHashCredential), 201)]
        public async Task<ActionResult<CapturedHashCredential>> CreateHashCredential([FromBody]CapturedHashCredential credential)
        {
            try
            {
                CapturedHashCredential addedCredential = await _service.CreateHashCredential(credential);
                return CreatedAtRoute(nameof(GetHashCredential), new { id = addedCredential.Id }, addedCredential);
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

        // POST api/credentials/tickets
        // <summary>
        // Create a CapturedTicketCredential
        // </summary>
        [HttpPost("tickets", Name = "CreateTicketCredential")]
        [ProducesResponseType(typeof(CapturedTicketCredential), 201)]
        public async Task<ActionResult<CapturedTicketCredential>> CreateTicketCredential([FromBody]CapturedTicketCredential credential)
        {
            try
            {
                CapturedTicketCredential addedCredential = await _service.CreateTicketCredential(credential);
                return CreatedAtRoute(nameof(GetHashCredential), new { id = addedCredential.Id }, addedCredential);
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

        // PUT api/credentials/passwords
        // <summary>
        // Edit a CapturedPasswordCredential
        // </summary>
        [HttpPut("passwords", Name = "EditPasswordCredential")]
        public async Task<ActionResult<CapturedPasswordCredential>> EditPasswordCredential([FromBody] CapturedPasswordCredential credential)
        {
            try
            {
                return await _service.EditPasswordCredential(credential);
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

        // PUT api/credentials/hashes
        // <summary>
        // Edit a CapturedHashCredential
        // </summary>
        [HttpPut("hashes", Name = "EditHashCredential")]
        public async Task<ActionResult<CapturedHashCredential>> EditHashCredential([FromBody] CapturedHashCredential credential)
        {
            try
            {
                return await _service.EditHashCredential(credential);
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

        // PUT api/credentials/tickets
        // <summary>
        // Edit a CapturedTicketCredential
        // </summary>
        [HttpPut("tickets", Name = "EditTicketCredential")]
        public async Task<ActionResult<CapturedTicketCredential>> EditTicketCredential([FromBody] CapturedTicketCredential credential)
        {
            try
            {
                return await _service.EditTicketCredential(credential);
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

        // DELETE api/credentials/{id}
        // <summary>
        // Delete a CapturedCredential
        // </summary>
        [HttpDelete("{id}", Name = "DeleteCredential")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteCredential(int id)
        {
            try
            {
                await _service.DeleteCredential(id);
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

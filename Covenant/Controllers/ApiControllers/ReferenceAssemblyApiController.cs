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
    [Authorize(Policy = "RequireJwtBearer")]
    [ApiController]
    [Route("api/referenceassemblies")]
    public class ReferenceAssemblyApiController : Controller
    {
        private readonly CovenantContext _context;

        public ReferenceAssemblyApiController(CovenantContext context)
        {
            _context = context;
        }

        // GET: api/referenceassemblies
        [HttpGet(Name = "GetReferenceAssemblies")]
        public async Task<ActionResult<IEnumerable<ReferenceAssembly>>> GetReferenceAssemblies()
        {
            return Ok(await _context.GetReferenceAssemblies());
        }

        // GET api/referenceassemblies/{id}
        [HttpGet("{id}", Name = "GetReferenceAssembly")]
        public async Task<ActionResult<ReferenceAssembly>> GetReferenceAssembly(int id)
        {
            try
            {
                return await _context.GetReferenceAssembly(id);
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

        // POST api/referenceassemblies
        [HttpPost(Name = "CreateReferenceAssembly")]
        public async Task<ActionResult<ReferenceAssembly>> CreateReferenceAssembly([FromBody]ReferenceAssembly assembly)
        {
            try
            {
                ReferenceAssembly createdAssembly = await _context.CreateReferenceAssembly(assembly);
                return CreatedAtRoute(nameof(GetReferenceAssembly), new { id = createdAssembly.Id }, createdAssembly);
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

        // PUT api/referenceassemblies
        [HttpPut(Name = "EditReferenceAssembly")]
        public async Task<ActionResult<ReferenceAssembly>> EditReferenceAssembly([FromBody]ReferenceAssembly assembly)
        {
            try
            {
                return await _context.EditReferenceAssembly(assembly);
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

        // DELETE api/referenceassemblies/{id}
        [HttpDelete("{id}", Name = "DeleteReferenceAssembly")]
        public async Task<ActionResult> DeleteReferenceAssembly(int id)
        {
            try
            {
                await _context.DeleteReferenceAssembly(id);
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

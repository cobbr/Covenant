// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models.Grunts;

namespace Covenant.Controllers
{
    [ApiController, Route("api/implanttemplates"), Authorize(Policy = "RequireJwtBearer")]
    public class ImplantTemplateApiController : Controller
    {
        private readonly ICovenantService _service;

        public ImplantTemplateApiController(ICovenantService service)
        {
            _service = service;
        }

        // GET: api/implanttemplates
        // <summary>
        // Get a list of ImplantTemplates
        // </summary>
        [HttpGet(Name = "GetImplantTemplates")]
        public async Task<ActionResult<IEnumerable<ImplantTemplate>>> GetImplantTemplates()
        {
            return Ok(await _service.GetImplantTemplates());
        }

        // GET api/implanttemplates/{id}
        // <summary>
        // Get a ImplantTemplate by id
        // </summary>
        [HttpGet("{id:int}", Name = "GetImplantTemplate")]
        public async Task<ActionResult<ImplantTemplate>> GetImplantTemplate(int id)
        {
            try
            {
                return await _service.GetImplantTemplate(id);
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

        // GET: api/implanttemplates/{name}
        // <summary>
        // Get a ImplantTemplate by Name
        // </summary>
        [HttpGet("{name}", Name = "GetImplantTemplateByName")]
        public async Task<ActionResult<ImplantTemplate>> GetImplantTemplateByName(string name)
        {
            try
            {
                return await _service.GetImplantTemplateByName(name);
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

        // POST api/implanttemplates
        // <summary>
        // Create an ImplantTemplate
        // </summary>
        [HttpPost(Name = "CreateImplantTemplate")]
        [ProducesResponseType(typeof(ImplantTemplate), 201)]
        public async Task<ActionResult<ImplantTemplate>> CreateImplantTemplate([FromBody]ImplantTemplate template)
        {
            try
            {
                ImplantTemplate createdTemplate = await _service.CreateImplantTemplate(template);
                return CreatedAtRoute(nameof(GetImplantTemplate), new { id = createdTemplate.Id }, createdTemplate);
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

        // PUT api/implanttemplates
        // <summary>
        // Edit an ImplantTemplate
        // </summary>
        [HttpPut(Name = "EditImplantTemplate")]
        public async Task<ActionResult<ImplantTemplate>> EditImplantTemplate([FromBody] ImplantTemplate template)
        {
            try
            {
                return await _service.EditImplantTemplate(template);
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

        // DELETE api/implanttemplates/{id}
        // <summary>
        // Delete an ImplantTemplate
        // </summary>
        [HttpDelete("{id}", Name = "DeleteImplantTemplate")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteImplantTemplate(int id)
        {
            try
            {
                await _service.DeleteImplantTemplate(id);
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

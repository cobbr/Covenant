// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models.Covenant;

namespace Covenant.Controllers
{
    [ApiController, Route("api/events"), Authorize]
    public class EventApiController : Controller
    {
        private readonly ICovenantService _service;

        public EventApiController(ICovenantService service)
        {
            _service = service;
        }

        // GET: api/events
        // <summary>
        // Get a list of Events
        // </summary>
        [HttpGet(Name = "GetEvents")]
        public async Task<ActionResult<IEnumerable<Event>>> GetEvents()
        {
            return Ok(await _service.GetEvents());
        }

        // GET api/events/{id}
        // <summary>
        // Get an Event by id
        // </summary>
        [HttpGet("{id}", Name = "GetEvent")]
        public async Task<ActionResult<Event>> GetEvent(int id)
        {
            try
            {
                return await _service.GetEvent(id);
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

        // GET: api/events/time
        // <summary>
        // Get Covenant's current DateTime
        // </summary>
        [HttpGet("time", Name = "GetEventTime")]
        public async Task<ActionResult<long>> GetEventTime()
        {
            try
            {
                return await _service.GetEventTime();
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

        // GET: api/events/range/{fromdate}
        // <summary>
        // Get a list of Events that occurred after the specified DateTime
        // </summary>
        [HttpGet("range/{fromdate}", Name = "GetEventsAfter")]
        public async Task<ActionResult<IEnumerable<Event>>> GetEventsAfter(long fromdate)
        {
            try
            {
                return Ok(await _service.GetEventsAfter(fromdate));
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

        // GET: api/events/range/{fromdate}/{todate}
        // <summary>
        // Get a list of Events that occurred between the range of specified DateTimes
        // </summary>
        [HttpGet("range/{fromdate}/{todate}", Name = "GetEventsRange")]
        public async Task<ActionResult<IEnumerable<Event>>> GetEventsRange(long fromdate, long todate)
        {
            try
            {
                return Ok(await _service.GetEventsRange(fromdate, todate));
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

		// POST api/events
		// <summary>
		// Create an Event
		// </summary>
		[HttpPost(Name = "CreateEvent")]
		[ProducesResponseType(typeof(Event), 201)]
		public async Task<ActionResult<Event>> CreateEvent([FromBody]Event anEvent)
		{
            try
            {
                Event createdEvent = await _service.CreateEvent(anEvent);
                return CreatedAtRoute(nameof(GetEvent), new { id = createdEvent.Id }, createdEvent);
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

        // GET: api/events/download/{id}
        // <summary>
        // Get a DownloadEvent
        // </summary>
        [HttpGet("download/{id}", Name = "GetDownloadEvent")]
        public async Task<ActionResult<DownloadEvent>> GetDownloadEvent(int id)
        {
            try
            {
                return await _service.GetDownloadEvent(id);
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

        // GET: api/events/download/{id}/download
        // <summary>
        // Get a downloaded file
        // </summary>
        [HttpGet("download/{id}/download", Name = "GetDownloadFile")]
        public async Task<ActionResult> GetDownloadFile(int id)
        {
            try
            {
                DownloadEvent download = await _service.GetDownloadEvent(id);
                string ext = Path.GetExtension(download.FileName);
                string ct = ext == null ? Common.DefaultContentTypeMapping : Common.ContentTypeMappings[ext];
                ct = string.IsNullOrEmpty(ct) ? Common.DefaultContentTypeMapping : ct;
                return File(download.ReadDownload(), ct, Utilities.GetSanitizedFilename(download.FileName));
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

        // POST api/events/download
        // <summary>
        // Post a downloaded file or portion of a downloaded file
        // </summary>
        [HttpPost("download", Name = "CreateDownloadEvent")]
        [ProducesResponseType(typeof(Event), 201)]
        public async Task<ActionResult<DownloadEvent>> CreateDownloadEvent([FromBody]DownloadEventContent downloadEvent)
        {
            try
            {
                DownloadEvent createdEvent = await _service.CreateDownloadEvent(downloadEvent);
                return CreatedAtRoute(nameof(GetDownloadEvent), new { id = createdEvent.Id }, createdEvent);
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

        // GET: api/events/screenshot/{id}
        // <summary>
        // Get a ScreenshotEvent
        // </summary>
        [HttpGet("screenshot/{id}", Name = "GetScreenshotEvent")]
        public async Task<ActionResult<ScreenshotEvent>> GetScreenshotEvent(int id)
        {
            try
            {
                return await _service.GetScreenshotEvent(id);
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

        // GET: api/events/screenshot/{id}/download
        // <summary>
        // Get a screenshot file
        // </summary>
        [HttpGet("screenshot/{id}/download", Name = "GetScreenshotFile")]
        public async Task<ActionResult> GetScreenshotFile(int id)
        {
            try
            {
                ScreenshotEvent screenshot = await _service.GetScreenshotEvent(id);
                string ext = Path.GetExtension(screenshot.FileName);
                string ct = ext == null ? Common.DefaultContentTypeMapping : Common.ContentTypeMappings[ext];
                ct = string.IsNullOrEmpty(ct) ? Common.DefaultContentTypeMapping : ct;
                return File(screenshot.ReadDownload(), ct, Utilities.GetSanitizedFilename(screenshot.FileName));
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

        // POST api/events/screenshot
        // <summary>
        // Post a downloaded file or portion of a screenshot file
        // </summary>
        [HttpPost("screenshot", Name = "CreateScreenshotEvent")]
        [ProducesResponseType(typeof(ScreenshotEvent), 201)]
        public async Task<ActionResult<ScreenshotEvent>> CreateScreenshotEvent([FromBody] ScreenshotEventContent screenshotEvent)
        {
            try
            {
                ScreenshotEvent createdEvent = await _service.CreateScreenshotEvent(screenshotEvent);
                return CreatedAtRoute(nameof(GetScreenshotEvent), new { id = createdEvent.Id }, createdEvent);
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

        // DELETE api/events/{id}
        // <summary>
        // Delete an Event
        // </summary>
        [HttpDelete("{id}", Name = "DeleteEvent")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteEvent(int id)
        {
            try
            {
                await _service.DeleteEvent(id);
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

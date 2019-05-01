// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;

namespace Covenant.Controllers
{
	[Authorize]
	[ApiController]
    [Route("api/events")]
    public class EventApiController : Controller
    {
        private readonly CovenantContext _context;

        public EventApiController(CovenantContext context)
        {
            _context = context;
        }

        // GET: api/events
        // <summary>
        // Get a list of Events
        // </summary>
        [HttpGet(Name = "GetEvents")]
        public ActionResult<IEnumerable<Event>> GetEvents()
        {
            return _context.Events.ToList();
        }

        // GET api/events/{id}
        // <summary>
        // Get an Event by id
        // </summary>
        [HttpGet("{id}", Name = "GetEvent")]
        public ActionResult<Event> GetEvent(int id)
        {
            var anEvent = _context.Events.FirstOrDefault(E => E.Id == id);
            if (anEvent == null)
            {
                return NotFound($"NotFound - Event with id: {id}");
            }
            return Ok(anEvent);
        }

        // GET: api/events/time
        // <summary>
        // Get Covenant's current DateTime
        // </summary>
        [HttpGet("time", Name = "GetTime")]
        public ActionResult<long> GetTime()
        {
            return Ok(DateTime.UtcNow.ToBinary());
        }

        // GET: api/events/range/{fromdate}
        // <summary>
        // Get a list of Events that occurred after the specified DateTime
        // </summary>
        [HttpGet("range/{fromdate}", Name = "GetEventsAfter")]
        public ActionResult<IEnumerable<Event>> GetEventsAfter(long fromdate)
        {
            DateTime start = DateTime.FromBinary(fromdate);
            return _context.Events.Where(E => E.Time.CompareTo(start) >= 0).ToList();
        }

        // GET: api/events/range/{fromdate}/{todate}
        // <summary>
        // Get a list of Events that occurred between the range of specified DateTimes
        // </summary>
        [HttpGet("range/{fromdate}/{todate}", Name = "GetEventsRange")]
        public ActionResult<IEnumerable<Event>> GetEventsRange(long fromdate, long todate)
        {
            DateTime start = DateTime.FromBinary(fromdate);
            DateTime end = DateTime.FromBinary(todate);
            return _context.Events.Where(E => E.Time.CompareTo(start) >= 0 && E.Time.CompareTo(end) <= 0).ToList();
        }

		// POST api/events
		// <summary>
		// Create an Event
		// </summary>
		[HttpPost(Name = "CreateEvent")]
		[ProducesResponseType(typeof(Event), 201)]
		public ActionResult<Event> CreateEvent([FromBody]Event anEvent)
		{
			anEvent.Time = DateTime.UtcNow;
			_context.Events.Add(anEvent);
			_context.SaveChanges();
			return CreatedAtRoute(nameof(GetEvent), new { id = anEvent.Id }, anEvent);
		}

        // GET: api/events/download/{id}
        // <summary>
        // Get a DownloadEvent
        // </summary>
        [HttpGet("download/{id}", Name = "GetDownloadEvent")]
        public ActionResult<DownloadEvent> GetDownloadEvent(int id)
        {
            return ((DownloadEvent)_context.Events.FirstOrDefault(E => E.Id == id && E.Type == Event.EventType.Download));
        }

        // GET: api/events/download/{id}/content
        // <summary>
        // Get a downloaded file
        // </summary>
        [HttpGet("download/{id}/content", Name = "GetDownloadContent")]
        public ActionResult<string> GetDownloadContent(int id)
        {
            DownloadEvent theEvent = ((DownloadEvent)_context.Events.FirstOrDefault(E => E.Id == id));
            if (theEvent == null)
            {
                return NotFound($"NotFound - DownloadEvent with id: {id}"); ;
            }
            string filename = Path.Combine(Common.CovenantDownloadDirectory, theEvent.FileName);
            if (!System.IO.File.Exists(filename))
            {
                return BadRequest($"BadRequest - Path does not exist on disk: {filename}");
            }
            return Convert.ToBase64String(System.IO.File.ReadAllBytes(filename));
        }

        // POST api/events/download
        // <summary>
        // Post a downloaded file or portion of a downloaded file
        // </summary>
        [HttpPost("download", Name = "CreateDownloadEvent")]
        [ProducesResponseType(typeof(Event), 201)]
        public ActionResult CreateDownloadEvent([FromBody]DownloadEvent downloadEvent)
        {
            downloadEvent.Time = DateTime.UtcNow;
            downloadEvent.WriteToDisk();
            _context.Events.Add(downloadEvent);
            _context.SaveChanges();
            return CreatedAtRoute(nameof(GetEvent), new { id = downloadEvent.Id }, downloadEvent);
        }
    }
}

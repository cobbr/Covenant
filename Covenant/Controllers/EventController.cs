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
    [Route("api/[controller]s")]
    public class EventController : Controller
    {
        private readonly CovenantContext _context;

        public EventController(CovenantContext context)
        {
            _context = context;
        }

        // GET: api/events
        // <summary>
        // Get a list of Events
        // </summary>
        [HttpGet(Name = "GetEvents")]
        public IEnumerable<Event> GetEvents()
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
                return NotFound();
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
            return Ok(DateTime.Now.ToBinary());
        }

        // GET: api/events/range/{fromdate}
        // <summary>
        // Get a list of Events that occurred after the specified DateTime
        // </summary>
        [HttpGet("range/{fromdate}", Name = "GetEventsAfter")]
        public IEnumerable<Event> GetEventsAfter(long fromdate)
        {
            DateTime start = DateTime.FromBinary(fromdate);
            return _context.Events.Where(E => E.Time.CompareTo(start) >= 0).ToList();
        }

        // GET: api/events/range/{fromdate}/{todate}
        // <summary>
        // Get a list of Events that occurred between the range of specified DateTimes
        // </summary>
        [HttpGet("range/{fromdate}/{todate}", Name = "GetEventsRange")]
        public IEnumerable<Event> GetEventsRange(long fromdate, long todate)
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
			anEvent.Time = DateTime.Now;
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
                return NotFound();
            }
            return Ok(Convert.ToBase64String(System.IO.File.ReadAllBytes(Path.Combine(Common.CovenantDownloadDirectory, theEvent.FileName))));
        }

        // POST api/events/download
        // <summary>
        // Post a downloaded file or portion of a downloaded file
        // </summary>
        [HttpPost("download", Name = "CreateDownloadEvent")]
        [ProducesResponseType(typeof(Event), 201)]
        public ActionResult CreateDownloadEvent([FromBody]DownloadEvent downloadEvent)
        {
            downloadEvent.Time = DateTime.Now;
            byte[] contents = Convert.FromBase64String(downloadEvent.FileContents);
            if (downloadEvent.Progress == DownloadEvent.DownloadProgress.Complete)
            {
                System.IO.File.WriteAllBytes(
                    Path.Combine(Common.CovenantDownloadDirectory, downloadEvent.FileName),
                    contents
                );
            }
            else
            {
                using (var stream = new FileStream(Path.Combine(Common.CovenantDownloadDirectory, downloadEvent.FileName), FileMode.Append))
                {
                    stream.Write(contents, 0, contents.Length);
                }
            }
            _context.Events.Add(downloadEvent);
            _context.SaveChanges();
            return CreatedAtRoute(nameof(GetEvent), new { id = downloadEvent.Id }, downloadEvent);
        }
    }
}

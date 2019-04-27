// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Models;
using Covenant.Models.Indicators;

namespace Covenant.Controllers
{
    [Authorize(Policy = "RequireJwtBearer")]
    [ApiController]
    [Route("api/indicators")]
    public class IndicatorApiController : Controller
    {
        private readonly CovenantContext _context;

        public IndicatorApiController(CovenantContext context)
        {
            _context = context;
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
        public ActionResult<IEnumerable<Indicator>> GetIndicators()
        {
            return _context.Indicators.ToList();
        }

        // GET: api/indicators/files
        // <summary>
        // Get a list of FileIndicators
        // </summary>
        [HttpGet("files", Name = "GetFileIndicators")]
        public ActionResult<IEnumerable<FileIndicator>> GetFileIndicators()
        {
            return _context.Indicators.Where(I => I.Name == "FileIndicator").Select(I => (FileIndicator)I).ToList();
        }

        // GET: api/indicators/networks
        // <summary>
        // Get a list of NetworksIndicators
        // </summary>
        [HttpGet("networks", Name = "GetNetworkIndicators")]
        public ActionResult<IEnumerable<NetworkIndicator>> GetNetworkIndicators()
        {
            return _context.Indicators.Where(I => I.Name == "NetworkIndicator").Select(I => (NetworkIndicator)I).ToList();
        }

        // GET: api/indicators/targets
        // <summary>
        // Get a list of TargetIndicators
        // </summary>
        [HttpGet("targets", Name = "GetTargetIndicators")]
        public ActionResult<IEnumerable<TargetIndicator>> GetTargetIndicators()
        {
            return _context.Indicators.Where(I => I.Name == "TargetIndicator").Select(I => (TargetIndicator)I).ToList();
        }

        // GET api/indicators/{id}
        // <summary>
        // Get an Indicator by id
        // </summary>
        [HttpGet("{id}", Name = "GetIndicator")]
        public ActionResult<Indicator> GetIndicator(int id)
        {
            var indicator = _context.Indicators.FirstOrDefault(i => i.Id == id);
            if (indicator == null)
            {
                return NotFound($"NotFound - Indicator with id: {id}");
            }
            return indicator;
        }

        // GET: api/indicators/files/{id}
        // <summary>
        // Get a list of FileIndicators
        // </summary>
        [HttpGet("files/{id}", Name = "GetFileIndicator")]
        public ActionResult<FileIndicator> GetFileIndicator(int id)
        {
            var indicator = _context.Indicators.Where(I => I.Name == "FileIndicator").Select(I => (FileIndicator)I)
            .FirstOrDefault(i => i.Id == id);
            if (indicator == null)
            {
                return NotFound($"NotFound - FileIndicator with id: {id}");
            }
            return indicator;
        }

        // GET: api/indicators/networks/{id}
        // <summary>
        // Get a list of NetworksIndicators
        // </summary>
        [HttpGet("networks/{id}", Name = "GetNetworkIndicator")]
        public ActionResult<NetworkIndicator> GetNetworkIndicator(int id)
        {
            var indicator = _context.Indicators.Where(I => I.Name == "NetworkIndicator").Select(I => (NetworkIndicator)I)
            .FirstOrDefault(i => i.Id == id);
            if (indicator == null)
            {
                return NotFound($"NotFound - NetworkIndicator with id: {id}");
            }
            return indicator;
        }

        // GET: api/indicators/targets/{id}
        // <summary>
        // Get a list of TargetIndicators
        // </summary>
        [HttpGet("targets/{id}", Name = "GetTargetIndicator")]
        public ActionResult<TargetIndicator> GetTargetIndicator(int id)
        {
            var indicator = _context.Indicators.Where(I => I.Name == "TargetIndicator").Select(I => (TargetIndicator)I)
            .FirstOrDefault(i => i.Id == id);
            if (indicator == null)
            {
                return NotFound($"NotFound - TargetIndicator with id: {id}");
            }
            return indicator;
        }

        // POST api/indicators
        // <summary>
        // Create a Indicator
        // </summary>
        [HttpPost(Name = "CreateIndicator")]
        [ProducesResponseType(typeof(Indicator), 201)]
        public ActionResult<Indicator> CreateIndicator([FromBody]Indicator indicator)
        {
            _context.Indicators.Add(indicator);
            _context.SaveChanges();
            return CreatedAtRoute(nameof(GetIndicator), new { id = indicator.Id }, indicator);
        }

        // PUT api/indicators
        // <summary>
        // Edit a Indicator
        // </summary>
        [HttpPut(Name = "EditIndicator")]
        public ActionResult<Indicator> EditIndicator([FromBody] Indicator indicator)
        {
            var matching_indicator = _context.Indicators.FirstOrDefault(i => indicator.Id == i.Id);
            if (matching_indicator == null)
            {
                return NotFound($"NotFound - Indicator with id: {indicator.Id}");
            }

            matching_indicator.Name = indicator.Name;

            _context.Indicators.Update(matching_indicator);
            _context.SaveChanges();

            return matching_indicator;
        }

        // DELETE api/indicators/{id}
        // <summary>
        // Delete a Indicator
        // </summary>
        [HttpDelete("{id}", Name = "DeleteIndicator")]
        [ProducesResponseType(204)]
        public ActionResult DeleteIndicator(int id)
        {
            var indicator = _context.Indicators.FirstOrDefault(i => i.Id == id);
            if (indicator == null)
            {
                return NotFound($"NotFound - Indicator with id: {id}");
            }

            _context.Indicators.Remove(indicator);
            _context.SaveChanges();
            return new NoContentResult();
        }
    }
}

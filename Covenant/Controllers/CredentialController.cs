// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Models;
using Covenant.Models.Covenant;

namespace Covenant.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]s")]
    public class CredentialController : Controller
    {
        private readonly CovenantContext _context;

        public CredentialController(CovenantContext context)
        {
            _context = context;
        }

        // GET: api/credentials
        // <summary>
        // Get a list of CapturedCredentials
        // </summary>
        [HttpGet(Name = "GetCredentials")]
        public ActionResult<IEnumerable<CapturedCredential>> GetCredentials()
        {
            return _context.Credentials.ToList();
        }

        // GET: api/credentials/passwords
        // <summary>
        // Get a list of CapturedPasswordCredentials
        // </summary>
        [HttpGet("passwords", Name = "GetPasswordCredentials")]
        public ActionResult<IEnumerable<CapturedPasswordCredential>> GetPasswordCredentials()
        {
            return _context.Credentials.Where(P => P.Type == CapturedCredential.CredentialType.Password).Select(P => (CapturedPasswordCredential)P).ToList();
        }

        // GET: api/credentials/hashes
        // <summary>
        // Get a list of CapturedHashCredentials
        // </summary>
        [HttpGet("hashes", Name = "GetHashCredentials")]
        public ActionResult<IEnumerable<CapturedHashCredential>> GetHashCredentials()
        {
            return _context.Credentials.Where(P => P.Type == CapturedCredential.CredentialType.Hash).Select(H => (CapturedHashCredential)H).ToList();
        }

        // GET: api/credentials/tickets
        // <summary>
        // Get a list of CapturedTicketCredentials
        // </summary>
        [HttpGet("tickets", Name = "GetTicketCredentials")]
        public ActionResult<IEnumerable<CapturedTicketCredential>> GetTicketCredentials()
        {
            return _context.Credentials.Where(P => P.Type == CapturedCredential.CredentialType.Ticket).Select(T => (CapturedTicketCredential)T).ToList();
        }

        // GET api/credentials/{id}
        // <summary>
        // Get a CapturedCredential by id
        // </summary>
        [HttpGet("{id}", Name = "GetCredential")]
        public ActionResult<CapturedCredential> GetCredential(int id)
        {
            var credential = _context.Credentials.FirstOrDefault(c => c.Id == id);
            if (credential == null)
            {
                return NotFound($"NotFound - CapturedCredential with id: {id}");
            }
            return credential;
        }

        // GET api/credentials/passwords/{id}
        // <summary>
        // Get a CapturedPasswordCredential by id
        // </summary>
        [HttpGet("passwords/{id}", Name = "GetPasswordCredential")]
        public ActionResult<CapturedPasswordCredential> GetPasswordCredential(int id)
        {
            var credential = (CapturedPasswordCredential) _context.Credentials
                                .Where(C => C.Type == CapturedCredential.CredentialType.Password)
                                .FirstOrDefault(c => c.Id == id);
            if (credential == null)
            {
                return NotFound($"NotFound - CapturedPasswordCredential with id: {id}");
            }
            return credential;
        }

        // GET api/credentials/hashes/{id}
        // <summary>
        // Get a CapturedHashCredential by id
        // </summary>
        [HttpGet("hashes/{id}", Name = "GetHashCredential")]
        public ActionResult<CapturedHashCredential> GetHashCredential(int id)
        {
            var credential = (CapturedHashCredential) _context.Credentials
                                .Where(C => C.Type == CapturedCredential.CredentialType.Hash)
                                .FirstOrDefault(c => c.Id == id);
            if (credential == null)
            {
                return NotFound($"NotFound - CapturedHashCredential with id: {id}");
            }
            return credential;
        }

        // GET api/credentials/tickets/{id}
        // <summary>
        // Get a CapturedTicketCredential by id
        // </summary>
        [HttpGet("tickets/{id}", Name = "GetTicketCredential")]
        public ActionResult<CapturedTicketCredential> GetTicketCredential(int id)
        {
            var credential = (CapturedTicketCredential) _context.Credentials
                                .Where(C => C.Type == CapturedCredential.CredentialType.Ticket)
                                .FirstOrDefault(c => c.Id == id);
            if (credential == null)
            {
                return NotFound($"NotFound - CapturedTicketCredential with id: {id}");
            }
            return Ok(credential);
        }

        // POST api/credentials/passwords
        // <summary>
        // Create a CapturedPasswordCredential
        // </summary>
        [HttpPost("passwords", Name = "CreatePasswordCredential")]
        [ProducesResponseType(typeof(CapturedPasswordCredential), 201)]
        public ActionResult<CapturedPasswordCredential> CreatePasswordCredential([FromBody]CapturedPasswordCredential passwordCredential)
        {
            _context.Credentials.Add(passwordCredential);
            _context.SaveChanges();

            return CreatedAtRoute(nameof(GetPasswordCredential), new { id = passwordCredential.Id }, passwordCredential);
        }

        // POST api/credentials/hashes
        // <summary>
        // Create a CapturedHashCredential
        // </summary>
        [HttpPost("hashes", Name = "CreateHashCredential")]
        [ProducesResponseType(typeof(CapturedHashCredential), 201)]
        public ActionResult<CapturedHashCredential> CreateHashCredential([FromBody]CapturedHashCredential hashCredential)
        {
            _context.Credentials.Add(hashCredential);
            _context.SaveChanges();

            return CreatedAtRoute(nameof(GetHashCredential), new { id = hashCredential.Id }, hashCredential);
        }

        // POST api/credentials/tickets
        // <summary>
        // Create a CapturedTicketCredential
        // </summary>
        [HttpPost("tickets", Name = "CreateTicketCredential")]
        [ProducesResponseType(typeof(CapturedTicketCredential), 201)]
        public ActionResult<CapturedTicketCredential> CreateTicketCredential([FromBody]CapturedTicketCredential ticketCredential)
        {
            _context.Credentials.Add(ticketCredential);
            _context.SaveChanges();

            return CreatedAtRoute(nameof(GetTicketCredential), new { id = ticketCredential.Id }, ticketCredential);
        }

        // PUT api/credentials/passwords
        // <summary>
        // Edit a CapturedPasswordCredential
        // </summary>
        [HttpPut("passwords", Name = "EditPasswordCredential")]
        public ActionResult<CapturedPasswordCredential> EditPasswordCredential([FromBody] CapturedPasswordCredential passwordCredential)
        {
            CapturedPasswordCredential matching_passwordCredential = (CapturedPasswordCredential) _context.Credentials.FirstOrDefault(c => 
                c.Type == CapturedCredential.CredentialType.Password && passwordCredential.Id == c.Id
            );

            if (matching_passwordCredential == null)
            {
                return NotFound($"NotFound - CapturedPasswordCredential with id: {passwordCredential.Id}");
            }

            matching_passwordCredential.Username = passwordCredential.Username;
            matching_passwordCredential.Password = passwordCredential.Password;
            matching_passwordCredential.Type = passwordCredential.Type;

            _context.Credentials.Update(matching_passwordCredential);
            _context.SaveChanges();
            return matching_passwordCredential;
        }

        // PUT api/credentials/hashes
        // <summary>
        // Edit a CapturedHashCredential
        // </summary>
        [HttpPut("hashes", Name = "EditHashCredential")]
        public ActionResult<CapturedHashCredential> EditHashCredential([FromBody] CapturedHashCredential hashCredential)
        {
            CapturedHashCredential matching_hashCredential = (CapturedHashCredential)_context.Credentials.FirstOrDefault(c =>
                c.Type == CapturedCredential.CredentialType.Hash && hashCredential.Id == c.Id
            );

            if (matching_hashCredential == null)
            {
                return NotFound($"NotFound - CapturedHashCredential with id: {hashCredential.Id}");
            }

            matching_hashCredential.Username = hashCredential.Username;
            matching_hashCredential.Hash = hashCredential.Hash;
            matching_hashCredential.HashCredentialType = hashCredential.HashCredentialType;
            matching_hashCredential.Type = hashCredential.Type;

            _context.Credentials.Update(matching_hashCredential);
            _context.SaveChanges();
            return matching_hashCredential;
        }

        // PUT api/credentials/tickets
        // <summary>
        // Edit a CapturedTicketCredential
        // </summary>
        [HttpPut("tickets", Name = "EditTicketCredential")]
        public ActionResult<CapturedTicketCredential> EditTicketCredential([FromBody] CapturedTicketCredential ticketCredential)
        {
            CapturedTicketCredential matching_ticketCredential = (CapturedTicketCredential)_context.Credentials.FirstOrDefault(c =>
                c.Type == CapturedCredential.CredentialType.Password && ticketCredential.Id == c.Id
            );

            if (matching_ticketCredential == null)
            {
                return NotFound($"NotFound - CapturedTicketCredential with id: {ticketCredential.Id}");
            }

            matching_ticketCredential.Username = ticketCredential.Username;
            matching_ticketCredential.Ticket = ticketCredential.Ticket;
            matching_ticketCredential.TicketCredentialType = ticketCredential.TicketCredentialType;
            matching_ticketCredential.Type = ticketCredential.Type;

            _context.Credentials.Update(matching_ticketCredential);
            _context.SaveChanges();
            return matching_ticketCredential;
        }

        // DELETE api/credentials/{id}
        // <summary>
        // Delete a CapturedCredential
        // </summary>
        [HttpDelete("{id}", Name = "DeleteCredential")]
        [ProducesResponseType(204)]
        public ActionResult DeleteCredential(int id)
        {
            var credential = _context.Credentials.FirstOrDefault(c => c.Id == id);
            if (credential == null)
            {
                return NotFound($"NotFound - CapturedCredential with id: {id}");
            }

            _context.Credentials.Remove(credential);
            _context.SaveChanges();
            return new NoContentResult();
        }
    }
}

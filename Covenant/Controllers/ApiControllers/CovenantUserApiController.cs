// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;

using Microsoft.Extensions.Configuration;

using Covenant.Core;
using Covenant.Models;
using Covenant.Models.Covenant;

namespace Covenant.Controllers
{
	[Authorize(Policy = "RequireJwtBearer"), ApiController, Route("api")]
    public class CovenantUserApiController : Controller
    {
		private readonly CovenantContext _context;
		private readonly UserManager<CovenantUser> _userManager;
		private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<CovenantUser> _signInManager;
        private readonly IConfiguration _configuration;

		public CovenantUserApiController(CovenantContext context, UserManager<CovenantUser> userManager, RoleManager<IdentityRole> roleManager, SignInManager<CovenantUser> signInManager, IConfiguration configuration)
        {
			_context = context;
            _userManager = userManager;
			_roleManager = roleManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        // GET: api/users
        // Get a list of Users
        [HttpGet("users", Name = "GetUsers")]
		public async Task<ActionResult<IEnumerable<CovenantUser>>> GetUsers()
        {
            try
            {
                IEnumerable<CovenantUser> users = await _context.GetUsers();
                foreach (CovenantUser user in users)
                {
                    user.PasswordHash = "";
                }
                return Ok(users);
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

		// GET api/users/{id}
        // Get a User by id
        [HttpGet("users/{id}", Name = "GetUser")]
		public async Task<ActionResult<CovenantUser>> GetUser(string id)
        {
            try
            {
                CovenantUser user = await _context.GetUser(id);
                user.PasswordHash = "";
                return user;
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

        // GET: api/users/current
        // Get a list of Users
        [HttpGet("users/current", Name = "GetCurrentUser")]
        public async Task<ActionResult<CovenantUser>> GetCurrentUser()
        {
            try
            {
                CovenantUser user = await _context.GetCurrentUser(_userManager, HttpContext.User);
                user.PasswordHash = "";
                return user;
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

        // POST api/users/login
        // Login a User by password
        [AllowAnonymous]
        [HttpPost("users/login", Name = "Login")]
        public async Task<ActionResult<CovenantUserLoginResult>> Login([FromBody] CovenantUserLogin login)
        {
            try
            {
                return await _context.Login(_signInManager, _configuration, login);
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

        // POST api/users
        // Create a User
        [Authorize(Policy = "RequireJwtBearerRequireAdministratorRole")]
        [HttpPost("users", Name = "CreateUser")]
		[ProducesResponseType(typeof(CovenantUser), 201)]
		public async Task<ActionResult<CovenantUser>> CreateUser([FromBody] CovenantUserLogin login)
		{
            try
            {
                CovenantUser user = await _context.CreateUser(_userManager, login);
                return CreatedAtRoute(nameof(GetUser), new { id = user.Id }, user);
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

        // PUT api/users
        // Edit a User's password
        [HttpPut("users", Name = "EditUser")]
		public async Task<ActionResult<CovenantUser>> EditUser([FromBody] CovenantUserLogin user)
        {
            try
            {
                CovenantUser editedUser = await _context.EditUser(_userManager, HttpContext.User, user);
                editedUser.PasswordHash = "";
                return editedUser;
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

        // DELETE api/users/{id}
        // Delete a User
        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpDelete("users/{id}", Name = "DeleteUser")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteUser(string id)
        {
            try
            {
                await _context.DeleteUser(id);
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

		// GET: api/users/roles
        // Get a list of all UserRoles
        [HttpGet("users/roles", Name = "GetUsersRoles")]
		public async Task<ActionResult<IEnumerable<IdentityUserRole<string>>>> GetUserRoles()
        {
            try
            {
                return Ok(await _context.GetUserRoles());
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

        // GET: api/users/{id}/roles
        // Get a list of Roles for a User
        [HttpGet("users/{id}/roles", Name = "GetUserRoles")]
		public async Task<ActionResult<IEnumerable<IdentityUserRole<string>>>> GetUserRoles(string id)
        {
            try
            {
                return Ok(await _context.GetUserRoles(id));
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

		// GET: api/users/{id}/roles/{rid}
        // Get a Role for a User
		[HttpGet("users/{id}/roles/{rid}", Name = "GetUserRole")]
		public async Task<ActionResult<IdentityUserRole<string>>> GetUserRole(string id, string rid)
        {
            try
            {
                return await _context.GetUserRole(id, rid);
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

        // POST: api/users/{id}/roles/{rid}
        // Create a UserRole
        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpPost("users/{id}/roles/{rid}", Name = "CreateUserRole")]
		[ProducesResponseType(typeof(IdentityUserRole<string>), 201)]
		public async Task<ActionResult<IdentityUserRole<string>>> CreateUserRole(string id, string rid)
        {
            try
            {
                IdentityUserRole<string> userRole = await _context.CreateUserRole(_userManager, id, rid);
                return CreatedAtRoute(nameof(GetUserRole), new { id = id, rid = rid }, userRole);
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

        // DELETE api/users/{id}/roles/{rid}
        // Delete a UserRole
        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpDelete("users/{id}/roles/{rid}", Name = "DeleteUserRole")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteUserRole(string id, string rid)
        {
            try
            {
                await _context.DeleteUserRole(_userManager, id, rid);
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

		// GET: api/roles
        // Get a list of all Roles
        [HttpGet("roles", Name = "GetRoles")]
        public async Task<ActionResult<IEnumerable<IdentityRole>>> GetRoles()
        {
            try
            {
                return Ok(await _context.GetRoles());
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

		// GET: api/roles/{rid}
        // Get a list of Roles for a User
		[HttpGet("roles/{rid}", Name = "GetRole")]
		public async Task<ActionResult<IdentityRole>> GetRole(string rid)
        {
            try
            {
                return await _context.GetRole(rid);
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

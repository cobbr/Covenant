// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;

using Microsoft.Extensions.Configuration;

using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Core;
using Covenant.Data;

namespace Covenant.Controllers
{
	[Authorize(Policy = "RequireAdministratorRole")]
	[ApiController]
    [Route("api")]
    public class CovenantUserController : Controller
    {
		private readonly CovenantContext _context;
		private readonly UserManager<CovenantUser> _userManager;
		private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<CovenantUser> _signInManager;
        private readonly IConfiguration _configuration;

		public CovenantUserController(CovenantContext context, UserManager<CovenantUser> userManager, RoleManager<IdentityRole> roleManager, SignInManager<CovenantUser> signInManager, IConfiguration configuration)
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
		public IEnumerable<CovenantUser> GetUsers()
        {
            return _context.Users.ToList();
        }

		// GET api/users/{uid}
        // Get a User by id
        [HttpGet("users/{uid}", Name = "GetUser")]
		public ActionResult<CovenantUser> GetUser(string uid)
        {
			var user = _context.Users.FirstOrDefault(U => U.Id == uid);
			if (user == null)
            {
                return NotFound();
            }
			return Ok(user);
        }

        // POST api/users/login
        // Login a User by password
		[AllowAnonymous]
        [HttpPost("users/login", Name = "Login")]
        public async Task<ActionResult<CovenantUserLoginResult>> Login([FromBody] CovenantUserLogin login)
        {
            var result = await _signInManager.PasswordSignInAsync(login.UserName, login.Password, false, false);
            if (!result.Succeeded)
            {
                return new UnauthorizedResult();
            }
            CovenantUser user = _userManager.Users.FirstOrDefault(U => U.UserName == login.UserName);
			List<string> userRoles = _context.UserRoles.Where(UR => UR.UserId == user.Id).Select(UR => UR.RoleId).ToList();
			List<string> roles = _context.Roles.Where(R => userRoles.Contains(R.Id)).Select(R => R.Name).ToList();

            string token = Utilities.GenerateJwtToken(
				login.UserName, user.Id, roles.ToArray(),
                _configuration["JwtKey"], _configuration["JwtIssuer"],
                _configuration["JwtAudience"], _configuration["JwtExpireDays"]
            );
            return new CovenantUserLoginResult { success = true, token = token };
        }

		// POST api/users
        // Create a User
		[HttpPost("users", Name = "CreateUser")]
		[ProducesResponseType(typeof(CovenantUser), 201)]
		public ActionResult<CovenantUser> CreateUser([FromBody] CovenantUserLogin login)
		{
			CovenantUser user = new CovenantUser { UserName = login.UserName };
			_userManager.CreateAsync(user, login.Password).Wait();
			CovenantUser savedUser = _context.Users.FirstOrDefault(U => U.UserName == user.UserName);
			return CreatedAtRoute(nameof(GetUser), new { uid = savedUser.Id }, savedUser);
		}

        // PUT api/users
        // Edit a User
        [HttpPut("users", Name = "EditUser")]
		public ActionResult<CovenantUser> EditUser([FromBody] CovenantUser user)
        {
            var matching_user = _context.Users.FirstOrDefault(U => user.Id == U.Id);
			if (matching_user == null)
			{
				return NotFound();
			}
			_context.Users.Update(matching_user);
            _context.SaveChanges();
			return Ok(matching_user);
        }

		// DELETE api/users/{uid}
        // Delete a User
        [HttpDelete("users/{uid}", Name = "DeleteUser")]
        [ProducesResponseType(204)]
        public ActionResult DeleteUser(string uid)
        {
            var user = _context.Users.FirstOrDefault(U => U.Id == uid);
            if (user == null)
            {
                return NotFound();
            }
            var admins = from users in _context.Users
                         join userroles in _context.UserRoles on users.Id equals userroles.UserId
                         join roles in _context.Roles on userroles.RoleId equals roles.Id
                         where roles.Name == "Administrator"
                         select users.UserName;
            if (admins.Contains(user.UserName) && admins.Count() == 1)
            {
                return BadRequest();
            }
            _context.Users.Remove(user);
            _context.SaveChanges();
            return new NoContentResult();
        }

		// GET: api/users/roles
        // Get a list of all UserRoles
        [HttpGet("users/roles", Name = "GetUsersRoles")]
		public IEnumerable<IdentityUserRole<string>> GetUsersRoles()
        {
			return _context.UserRoles.ToList();
        }

        // GET: api/users/{uid}/roles
        // Get a list of Roles for a User
        [HttpGet("users/{uid}/roles", Name = "GetUserRoles")]
		public IEnumerable<IdentityUserRole<string>> GetUserRoles(string uid)
        {
			return _context.UserRoles.Where(UR => UR.UserId == uid).ToList();
        }

		// GET: api/users/{uid}/roles/{rid}
        // Get a list of Roles for a User
		[HttpGet("users/{uid}/roles/{rid}", Name = "GetUserRole")]
		public ActionResult<IdentityUserRole<string>> GetUserRole(string uid, string rid)
        {
			IdentityUserRole<string> userRole = _context.UserRoles.FirstOrDefault(UR => UR.UserId == uid && UR.RoleId == rid);
            if (userRole == null)
			{
				return NotFound();
			}
			return Ok(userRole);
        }

		// POST: api/users/{uid}/roles/{rid}
        // Create a UserRole
		[HttpPost("users/{uid}/roles/{rid}", Name = "CreateUserRole")]
		[ProducesResponseType(typeof(IdentityUserRole<string>), 201)]
		public ActionResult<IdentityUserRole<string>> CreateUserRole(string uid, string rid)
        {
			CovenantUser user = _context.Users.FirstOrDefault(U => U.Id == uid);
			IdentityRole role = _context.Roles.FirstOrDefault(R => R.Id == rid);

			_userManager.AddToRoleAsync(user, role.Name).Wait();
			IdentityUserRole<string> userRole = _context.UserRoles.FirstOrDefault(UR => UR.UserId == uid && UR.RoleId == rid);
			return CreatedAtRoute(nameof(GetUserRole), new { uid = uid, rid = rid }, userRole);
        }

		// DELETE api/users/{uid}/roles/{rid}
        // Delete a UserRole
		[HttpDelete("users/{uid}/roles/{rid}", Name = "DeleteUserRole")]
        [ProducesResponseType(204)]
        public ActionResult DeleteUserRole(string uid, string rid)
        {
			var userRole = _context.UserRoles.FirstOrDefault(UR => UR.UserId == uid && UR.RoleId == rid);
			if (userRole == null)
            {
                return NotFound();
            }
            var adminUserRoles = from users in _context.Users
                         join userroles in _context.UserRoles on users.Id equals userroles.UserId
                         join roles in _context.Roles on userroles.RoleId equals roles.Id
                         where roles.Name == "Administrator"
                         select userroles;
            if (adminUserRoles.Contains(userRole) && adminUserRoles.Count() == 1)
            {
                return BadRequest();
            }

			_context.UserRoles.Remove(userRole);
            _context.SaveChanges();
            return new NoContentResult();
        }

		// GET: api/roles
        // Get a list of all Roles
        [HttpGet("roles", Name = "GetRoles")]
        public IEnumerable<IdentityRole> GetRoles()
        {
            return _context.Roles.ToList();
        }

		// GET: api/roles/{rid}
        // Get a list of Roles for a User
		[HttpGet("roles/{rid}", Name = "GetRole")]
		public ActionResult<IdentityRole> GetRole(string rid)
        {
			var role = _context.Roles.FirstOrDefault(R => R.Id == rid);
			if (role == null)
            {
                return NotFound();
            }
			return Ok(role);
        }
    }
}

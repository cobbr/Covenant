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
	[Authorize(Policy = "RequireJwtBearer")]
	[ApiController]
    [Route("api")]
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

        private CovenantUser GetCurrentAPIUser()
        {
            Task<CovenantUser> task = _userManager.GetUserAsync(HttpContext.User);
            task.Wait();
            return task.Result;
        }

        private Microsoft.AspNetCore.Identity.SignInResult GetPasswordSignInResult(string username, string password)
        {
            Task<Microsoft.AspNetCore.Identity.SignInResult> task = _signInManager.PasswordSignInAsync(username, password, false, false);
            task.Wait();
            return task.Result;
        }

        private IdentityResult CreateCovenantUser(CovenantUser user, string password)
        {
            Task<IdentityResult> task = _userManager.CreateAsync(user, password);
            task.Wait();
            return task.Result;
        }

        private IdentityResult CreateUserRole(CovenantUser user, string rolename)
        {
            Task<IdentityResult> task = _userManager.AddToRoleAsync(user, rolename);
            task.Wait();
            return task.Result;
        }

        // GET: api/users/current
        // Get a list of Users
        [HttpGet("users/current", Name = "GetCurrentUser")]
        public ActionResult<CovenantUser> GetCurrentUser()
        {
            CovenantUser user = GetCurrentAPIUser();
            if (user == null)
            {
                return NotFound($"NotFound - Could not identify current username");
            }
            user.PasswordHash = "";
            user.SecurityStamp = "";
            return user;
        }

        // GET: api/users
        // Get a list of Users
        [HttpGet("users", Name = "GetUsers")]
		public ActionResult<IEnumerable<CovenantUser>> GetUsers()
        {
            List<CovenantUser> users = _context.Users.ToList();
            foreach(CovenantUser user in users)
            {
                // Hide sensitive information
                user.PasswordHash = "";
                user.SecurityStamp = "";
            }
            return users;
        }

		// GET api/users/{id}
        // Get a User by id
        [HttpGet("users/{id}", Name = "GetUser")]
		public ActionResult<CovenantUser> GetUser(string id)
        {
			var user = _context.Users.FirstOrDefault(U => U.Id == id);
			if (user == null)
            {
                return NotFound($"NotFound - Grunt with id: {id}");
            }
            user.PasswordHash = "";
            user.SecurityStamp = "";
			return user;
        }

        // POST api/users/login
        // Login a User by password
		[AllowAnonymous]
        [HttpPost("users/login", Name = "Login")]
        public ActionResult<CovenantUserLoginResult> Login([FromBody] CovenantUserLogin login)
        {
            Microsoft.AspNetCore.Identity.SignInResult result = this.GetPasswordSignInResult(login.UserName, login.Password);
            if (!result.Succeeded)
            {
                return new UnauthorizedResult();
            }
            CovenantUser user = _userManager.Users.FirstOrDefault(U => U.UserName == login.UserName);
            if (user == null)
            {
                return NotFound($"NotFound - User with username: {login.UserName}");
            }
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
        [Authorize(Policy = "RequireJwtBearerRequireAdministratorRole")]
        [HttpPost("users", Name = "CreateUser")]
		[ProducesResponseType(typeof(CovenantUser), 201)]
		public ActionResult<CovenantUser> CreateUser([FromBody] CovenantUserLogin login)
		{
			CovenantUser user = new CovenantUser { UserName = login.UserName };
            IdentityResult result = this.CreateCovenantUser(user, login.Password);
            if(!result.Succeeded)
            {
                List<IdentityError> errors = result.Errors.ToList();
                string ErrorMessage = $"BadRequest - Could not create CovenantUser: {login.UserName}";
                foreach (IdentityError error in result.Errors)
                {
                    ErrorMessage += Environment.NewLine + error.Description;
                }
                return BadRequest(ErrorMessage);
            }

            CovenantUser savedUser = _context.Users.FirstOrDefault(U => U.UserName == user.UserName);
            if (savedUser == null)
            {
                return NotFound($"NotFound - Could not find CovenantUser with username: {login.UserName}");
            }
            string savedRoles = String.Join(",", _context.UserRoles.Where(UR => UR.UserId == savedUser.Id).ToList());

            DateTime eventTime = DateTime.UtcNow;
            _context.Events.Add(new Event
            {
                Time = eventTime,
                MessageHeader = "[" + eventTime + " UTC] User: " + savedUser.UserName + " with roles: " + savedRoles + " has been created!",
                Level = Event.EventLevel.Highlight,
                Context = "Users"
            });

            return CreatedAtRoute(nameof(GetUser), new { id = savedUser.Id }, savedUser);
		}

        // PUT api/users
        // Edit a User's password
        [HttpPut("users", Name = "EditUser")]
		public ActionResult<CovenantUser> EditUser([FromBody] CovenantUserLogin user)
        {
            var matching_user = _context.Users.FirstOrDefault(U => user.UserName == U.UserName);
			if (matching_user == null)
			{
				return NotFound($"NotFound - Could not find CovenantUser with username: {user.UserName}");
			}
            CovenantUser currentUser = GetCurrentAPIUser();
            var admins = from users in _context.Users
                         join userroles in _context.UserRoles on users.Id equals userroles.UserId
                         join roles in _context.Roles on userroles.RoleId equals roles.Id
                         where roles.Name == "Administrator"
                         select users.UserName;
            if (currentUser.UserName != matching_user.UserName && !admins.Contains(currentUser.UserName))
            {
                return BadRequest($"BadRequest - Current user: {currentUser.UserName} is not an Administrator and cannot change password of user: {user.Password}");
            }
            matching_user.PasswordHash = _userManager.PasswordHasher.HashPassword(matching_user, user.Password);
            Task<IdentityResult> task = _userManager.UpdateAsync(matching_user);
            task.Wait();
            if (!task.Result.Succeeded)
            {
                return BadRequest($"BadRequest - Could not set new password for CovenantUser with username: {user.UserName}");
            }
            _context.Users.Update(matching_user);
            _context.SaveChanges();
            matching_user.PasswordHash = "";
            matching_user.SecurityStamp = "";
			return matching_user;
        }

        // DELETE api/users/{id}
        // Delete a User
        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpDelete("users/{id}", Name = "DeleteUser")]
        [ProducesResponseType(204)]
        public ActionResult DeleteUser(string id)
        {
            var user = _context.Users.FirstOrDefault(U => U.Id == id);
            if (user == null)
            {
                return NotFound($"NotFound - Could not find CovenantUser with id: {id}");
            }
            var admins = from users in _context.Users
                         join userroles in _context.UserRoles on users.Id equals userroles.UserId
                         join roles in _context.Roles on userroles.RoleId equals roles.Id
                         where roles.Name == "Administrator"
                         select users.UserName;
            if (admins.Contains(user.UserName) && admins.Count() == 1)
            {
                string ErrorMessage = $"BadRequest - Could not delete CovenantUser with id: {id}";
                ErrorMessage += "Can't delete the last Administrative user.";
                return BadRequest(ErrorMessage);
            }
            _context.Users.Remove(user);
            _context.SaveChanges();
            return new NoContentResult();
        }

		// GET: api/users/roles
        // Get a list of all UserRoles
        [HttpGet("users/roles", Name = "GetUsersRoles")]
		public ActionResult<IEnumerable<IdentityUserRole<string>>> GetUsersRoles()
        {
			return _context.UserRoles.ToList();
        }

        // GET: api/users/{id}/roles
        // Get a list of Roles for a User
        [HttpGet("users/{id}/roles", Name = "GetUserRoles")]
		public ActionResult<IEnumerable<IdentityUserRole<string>>> GetUserRoles(string id)
        {
			return _context.UserRoles.Where(UR => UR.UserId == id).ToList();
        }

		// GET: api/users/{id}/roles/{rid}
        // Get a Role for a User
		[HttpGet("users/{id}/roles/{rid}", Name = "GetUserRole")]
		public ActionResult<IdentityUserRole<string>> GetUserRole(string id, string rid)
        {
			IdentityUserRole<string> userRole = _context.UserRoles.FirstOrDefault(UR => UR.UserId == id && UR.RoleId == rid);
            if (userRole == null)
			{
				return NotFound($"NotFound - Could not find UserRole with user id: {id} and role id: {rid}");
			}
			return userRole;
        }

        // POST: api/users/{id}/roles/{rid}
        // Create a UserRole
        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpPost("users/{id}/roles/{rid}", Name = "CreateUserRole")]
		[ProducesResponseType(typeof(IdentityUserRole<string>), 201)]
		public ActionResult<IdentityUserRole<string>> CreateUserRole(string id, string rid)
        {
			CovenantUser user = _context.Users.FirstOrDefault(U => U.Id == id);
			IdentityRole role = _context.Roles.FirstOrDefault(R => R.Id == rid);
            if (user == null)
            {
                return NotFound($"NotFound - Could not find CovenantUser with id: {id}");
            }
            if (role == null)
            {
                return NotFound($"NotFound - Could not find UserRole with rid: {rid}");
            }

            IdentityResult result = this.CreateUserRole(user, role.Name);
            if (!result.Succeeded)
            {
                string ErrorMessage = $"BadRequest - Could not add CovenantUser: {user.UserName} to role: {role.Name}";
                foreach (IdentityError error in result.Errors)
                {
                    ErrorMessage += Environment.NewLine + error.Description;
                }
                return BadRequest(ErrorMessage);
            }
            IdentityUserRole<string> userRole = _context.UserRoles.FirstOrDefault(UR => UR.UserId == id && UR.RoleId == rid);
            if (userRole == null)
            {
                return NotFound($"NotFound - Could not find UserRole with user id: {id} and role id: {rid}");
            }
            return CreatedAtRoute(nameof(GetUserRole), new { id = id, rid = rid }, userRole);
        }

        // DELETE api/users/{id}/roles/{rid}
        // Delete a UserRole
        [Authorize(Policy = "RequireAdministratorRole")]
        [HttpDelete("users/{id}/roles/{rid}", Name = "DeleteUserRole")]
        [ProducesResponseType(204)]
        public ActionResult DeleteUserRole(string id, string rid)
        {
			var userRole = _context.UserRoles.FirstOrDefault(UR => UR.UserId == id && UR.RoleId == rid);
			if (userRole == null)
            {
                return NotFound($"NotFound - Could not find UserRole with user id: {id} and role id: {rid}");
            }
            var adminUserRoles = from users in _context.Users
                         join userroles in _context.UserRoles on users.Id equals userroles.UserId
                         join roles in _context.Roles on userroles.RoleId equals roles.Id
                         where roles.Name == "Administrator"
                         select userroles;
            if (adminUserRoles.Contains(userRole) && adminUserRoles.Count() == 1)
            {
                string ErrorMessage = $"BadRequest - Could not remove CovenantUser with id: {id} from role";
                ErrorMessage += "Can't remove the last Administrative user.";
                return BadRequest(ErrorMessage);
            }

			_context.UserRoles.Remove(userRole);
            _context.SaveChanges();
            return new NoContentResult();
        }

		// GET: api/roles
        // Get a list of all Roles
        [HttpGet("roles", Name = "GetRoles")]
        public ActionResult<IEnumerable<IdentityRole>> GetRoles()
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
                return NotFound($"NotFound - Could not find UserRoles with id: {rid}");
            }
			return role;
        }
    }
}

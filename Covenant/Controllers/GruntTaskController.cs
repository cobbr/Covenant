// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

using Covenant.Models;
using Covenant.Models.Grunts;

namespace Covenant.Controllers
{
	[Authorize]
	[ApiController]
    [Route("api/[controller]s")]
    public class GruntTaskController : Controller
    {
        private readonly CovenantContext _context;

        public GruntTaskController(CovenantContext context)
        {
            _context = context;
        }

        // GET: api/grunttasks
        // <summary>
        // Get Tasks
        // </summary>
        [HttpGet(Name = "GetGruntTasks")]
        public ActionResult<IEnumerable<GruntTask>> GetGruntTasks()
        {
            return _context.GruntTasks.Include(T => T.Options).ToList();
        }

        // GET: api/grunttasks/{id}
        // <summary>
        // Get a Task by Id
        // </summary>
        [HttpGet("{id:int}", Name = "GetGruntTask")]
        public ActionResult<GruntTask> GetGruntTask(int id)
        {
            GruntTask task = _context.GruntTasks.Include(T => T.Options).FirstOrDefault(T => T.Id == id);
            if (task == null)
            {
                return NotFound($"NotFound - GruntTask with id: {id}");
            }
            return task;
        }

        // GET: api/grunttasks/{taskname}
        // <summary>
        // Get a Task by Name
        // </summary>
        [HttpGet("{taskname}", Name = "GetGruntTaskByName")]
        public ActionResult<GruntTask> GetGruntTaskByName(string taskname)
        {
            GruntTask task = _context.GruntTasks.Include(T => T.Options).FirstOrDefault(T => T.Name.ToLower() == taskname.ToLower());
            if (task == null)
            {
                return NotFound($"NotFound - GruntTask with TaskName: {taskname}");
            }
            return task;
        }

        // POST api/grunttasks
        // <summary>
        // Create a Task
        // </summary>
        [HttpPost(Name = "CreateGruntTask")]
        [ProducesResponseType(typeof(GruntTask), 201)]
        public ActionResult<GruntTask> CreateGruntTask([FromBody] GruntTask task)
        {
            _context.GruntTasks.Add(task);
            GruntTask savedTask = _context.GruntTasks.Include(T => T.Options).FirstOrDefault(GT => GT.Id == task.Id);
            if (savedTask == null)
            {
                return NotFound($"NotFound - GruntTask with id: {task.Id}");
            }
            return CreatedAtRoute(nameof(GetGruntTask), new { id = task.Id }, task);
        }

        // PUT api/grunttasks
        // <summary>
        // Edit a Task
        // </summary>
        [HttpPut(Name = "EditGruntTask")]
        public ActionResult<GruntTask> EditGruntTask([FromBody] GruntTask task)
        {
            GruntTask updatingTask = _context.GruntTasks.Include(T => T.Options).FirstOrDefault(T => T.Id == task.Id);
            if (updatingTask == null)
            {
                return NotFound($"NotFound - GruntTask with id: {task.Id}");
            }
            updatingTask.Name = task.Name;
            updatingTask.Code = task.Code;
            updatingTask.Description = task.Description;
            updatingTask.EmbeddedResources = task.EmbeddedResources;
            updatingTask.ReferenceAssemblies = task.ReferenceAssemblies;
            updatingTask.ReferenceSourceLibraries = task.ReferenceSourceLibraries;
            updatingTask.TokenTask = task.TokenTask;
            foreach (GruntTask.GruntTaskOption option in updatingTask.Options)
            {
                GruntTask.GruntTaskOption t = task.Options.FirstOrDefault(O => O.Name == option.Name);
                if (t != null)
                {
                    option.Value = t.Value;
                }
            }
            _context.GruntTasks.Update(updatingTask);
            _context.SaveChanges();

            return updatingTask;
        }

        // DELETE api/grunttasks/{id}
        // <summary>
        // Delete a Task
        // </summary>
        [HttpDelete("{id}", Name = "DeleteGruntTask")]
        [ProducesResponseType(204)]
        public ActionResult DeleteGruntTask(int id)
        {
            GruntTask removingTask = _context.GruntTasks.Include(T => T.Options).FirstOrDefault(T => T.Id == id);

            if (removingTask == null)
            {
                return NotFound($"NotFound - GruntTask with id: {id}");
            }
            _context.GruntTasks.Remove(removingTask);
            _context.SaveChanges();

            return new NoContentResult();
        }
    }
}

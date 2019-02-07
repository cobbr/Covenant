// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

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
        public IEnumerable<GruntTask> GetGruntTasks()
        {
            List<GruntTask> tasks = _context.GruntTasks.ToList();
            tasks.ForEach(T => {
                T.Options = _context.GruntTaskOptions.Where(O => O.TaskId == T.Id).ToList();
            });
            return tasks;
        }

        // GET: api/grunttasks/{id}
        // <summary>
        // Get a Task by Id
        // </summary>
        [HttpGet("{id:int}", Name = "GetGruntTask")]
        public ActionResult<GruntTask> GetGruntTask(int id)
        {
            GruntTask task = _context.GruntTasks.FirstOrDefault(T => T.Id == id);
            if (task == null)
            {
                return NotFound();
            }
            task.Options = _context.GruntTaskOptions.Where(O => O.TaskId == task.Id).ToList();
            return Ok(task);
        }

        // GET: api/grunttasks/{taskname}
        // <summary>
        // Get a Task by Name
        // </summary>
        [HttpGet("{taskname}", Name = "GetGruntTaskByName")]
        public ActionResult<GruntTask> GetGruntTaskByName(string taskname)
        {
            GruntTask task = _context.GruntTasks.FirstOrDefault(T => T.Name.ToLower() == taskname.ToLower());
            if (task == null)
            {
                return NotFound();
            }
            task.Options = _context.GruntTaskOptions.Where(O => O.TaskId == task.Id).ToList();
            return Ok(task);
        }

        // POST api/grunttasks/{id}
        // <summary>
        // Create a Task
        // </summary>
        [HttpPost("{id}", Name = "CreateGruntTask")]
        [ProducesResponseType(typeof(GruntTask), 201)]
        public ActionResult<GruntTask> CreateGruntTask(int id, [FromBody] GruntTask task)
        {
            _context.GruntTasks.Add(task);
            task.Options.ForEach(O => {
                O.TaskId = task.Id;
                _context.GruntTaskOptions.Add(O);
            });
            _context.SaveChanges();

            return CreatedAtRoute(nameof(GetGruntTask), new { id = id }, task);
        }

        // PUT api/grunttasks/{id}
        // <summary>
        // Edit a Task
        // </summary>
        [HttpPut("{id}", Name = "EditGruntTask")]
        public ActionResult<GruntTask> EditGruntTask(int id, [FromBody] GruntTask task)
        {
            GruntTask updatingTask = _context.GruntTasks.FirstOrDefault(T => T.Id == id);
            if (updatingTask == null || updatingTask.Id != task.Id)
            {
                return NotFound();
            }
            updatingTask.Options = _context.GruntTaskOptions.Where(O => O.TaskId == updatingTask.Id).ToList();
            task.Options.ForEach(O =>
            {
                GruntTask.GruntTaskOption updatingTaskOption = updatingTask.Options.FirstOrDefault(TO => TO.Id == O.Id);
                if (updatingTaskOption == null)
                {
                    return;
                }
                updatingTaskOption.Value = O.Value;
            });
            _context.GruntTasks.Update(updatingTask);
            _context.SaveChanges();

            return Ok(updatingTask);
        }

        // DELETE api/grunttasks/{id}
        // <summary>
        // Delete a Task
        // </summary>
        [HttpDelete("{id}", Name = "DeleteGruntTask")]
        [ProducesResponseType(204)]
        public ActionResult DeleteGruntTask(int id)
        {
            GruntTask removingTask = _context.GruntTasks.FirstOrDefault(T => T.Id == id);

            if (removingTask == null)
            {
                return NotFound();
            }
            _context.GruntTasks.Remove(removingTask);
            _context.SaveChanges();

            return new NoContentResult();
        }
    }
}

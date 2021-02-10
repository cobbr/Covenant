// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Core;
using Covenant.Models.Launchers;
using Covenant.Models.Listeners;

namespace Covenant.Controllers
{
    [ApiController, Route("api/launchers"), Authorize(Policy = "RequireJwtBearer")]
    public class LauncherApiController : Controller
    {
        private readonly ICovenantService _service;

        public LauncherApiController(ICovenantService service)
        {
            _service = service;
        }

        // GET: api/launchers
        // <summary>
        // Get Launchers
        // </summary>
        [HttpGet(Name = "GetLaunchers")]
        public async Task<ActionResult<IEnumerable<Launcher>>> GetLaunchers()
        {
            return Ok(await _service.GetLaunchers());
        }

        // GET api/launchers/binary
        // <summary>
        // Get BinaryLaunchers
        // </summary>
        [HttpGet("binary", Name = "GetBinaryLaunchers")]
        public async Task<ActionResult<IEnumerable<BinaryLauncher>>> GetBinaryLaunchers()
        {
            try
            {
                return Ok(await _service.GetBinaryLaunchers());
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

        // GET api/launchers/servicebinary
        // <summary>
        // Get ServiceBinaryLaunchers
        // </summary>
        [HttpGet("servicebinary", Name = "GetServiceBinaryLaunchers")]
        public async Task<ActionResult<IEnumerable<BinaryLauncher>>> GetServiceBinaryLaunchers()
        {
            try
            {
                return Ok(await _service.GetServiceBinaryLaunchers());
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

        // GET api/launchers/shellcode
        // <summary>
        // Get ShellCodeLaunchers
        // </summary>
        [HttpGet("shellcode", Name = "GetShellCodeLaunchers")]
        public async Task<ActionResult<IEnumerable<ShellCodeLauncher>>> GetShellCodeLaunchers()
        {
            try
            {
                return Ok(await _service.GetShellCodeLaunchers());
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

        // GET api/launchers/powershell
        // <summary>
        // Get PowerShellLaunchers
        // </summary>
        [HttpGet("powershell", Name = "GetPowerShellLaunchers")]
        public async Task<ActionResult<IEnumerable<PowerShellLauncher>>> GetPowerShellLaunchers()
        {
            try
            {
                return Ok(await _service.GetPowerShellLaunchers());
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

        // GET api/launchers/msbuild
        // <summary>
        // Get MSBuildLaunchers
        // </summary>
        [HttpGet("msbuild", Name = "GetMSBuildLaunchers")]
        public async Task<ActionResult<IEnumerable<MSBuildLauncher>>> GetMSBuildLaunchers()
        {
            try
            {
                return Ok(await _service.GetMSBuildLaunchers());
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

        // GET api/launchers/installutil
        // <summary>
        // Get InstallUtilLaunchers
        // </summary>
        [HttpGet("installutil", Name = "GetInstallUtilLaunchers")]
        public async Task<ActionResult<IEnumerable<InstallUtilLauncher>>> GetInstallUtilLaunchers()
        {
            try
            {
                return Ok(await _service.GetInstallUtilLaunchers());
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

        // GET api/launchers/regsvr32
        // <summary>
        // Get Regsvr32Launchers
        // </summary>
        [HttpGet("regsvr32", Name = "GetRegsvr32Launchers")]
        public async Task<ActionResult<IEnumerable<Regsvr32Launcher>>> GetRegsvr32Launchers()
        {
            try
            {
                return Ok(await _service.GetRegsvr32Launchers());
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

        // GET api/launchers/mshta
        // <summary>
        // Get MshtaLaunchers
        // </summary>
        [HttpGet("mshta", Name = "GetMshtaLaunchers")]
        public async Task<ActionResult<MshtaLauncher>> GetMshtaLaunchers()
        {
            try
            {
                return Ok(await _service.GetMshtaLaunchers());
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

        // GET: api/launchers/{id}
        // <summary>
        // Get a Launcher
        // </summary>
        [HttpGet("{id}", Name = "GetLauncher")]
        public async Task<ActionResult<Launcher>> GetLauncher(int id)
        {
            return Ok(await _service.GetLauncher(id));
        }

        // GET api/launchers/binary/{id}
        // <summary>
        // Get a BinaryLauncher
        // </summary>
        [HttpGet("binary/{id}", Name = "GetBinaryLauncher")]
        public async Task<ActionResult<BinaryLauncher>> GetBinaryLauncher(int id)
        {
            try
            {
                return await _service.GetBinaryLauncher(id);
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

        // GET api/launchers/servicebinary/{id}
        // <summary>
        // Get a ServiceBinaryLauncher
        // </summary>
        [HttpGet("servicebinary/{id}", Name = "GetServiceBinaryLauncher")]
        public async Task<ActionResult<ServiceBinaryLauncher>> GetServiceBinaryLauncher(int id)
        {
            try
            {
                return await _service.GetServiceBinaryLauncher(id);
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

        // GET api/launchers/shellcode/{id}
        // <summary>
        // Get a ShellCodeLauncher
        // </summary>
        [HttpGet("shellcode/{id}", Name = "GetShellCodeLauncher")]
        public async Task<ActionResult<ShellCodeLauncher>> GetShellCodeLauncher(int id)
        {
            try
            {
                return await _service.GetShellCodeLauncher(id);
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

        // GET api/launchers/powershell/{id}
        // <summary>
        // Get a PowerShellLauncher
        // </summary>
        [HttpGet("powershell/{id}", Name = "GetPowerShellLauncher")]
        public async Task<ActionResult<PowerShellLauncher>> GetPowerShellLauncher(int id)
        {
            try
            {
                return await _service.GetPowerShellLauncher(id);
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

        // GET api/launchers/msbuild/{id}
        // <summary>
        // Get a MSBuildLauncher
        // </summary>
        [HttpGet("msbuild/{id}", Name = "GetMSBuildLauncher")]
        public async Task<ActionResult<MSBuildLauncher>> GetMSBuildLauncher(int id)
        {
            try
            {
                return await _service.GetMSBuildLauncher(id);
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

        // GET api/launchers/installutil/{id}
        // <summary>
        // Get a InstallUtilLauncher
        // </summary>
        [HttpGet("installutil/{id}", Name = "GetInstallUtilLauncher")]
        public async Task<ActionResult<InstallUtilLauncher>> GetInstallUtilLauncher(int id)
        {
            try
            {
                return await _service.GetInstallUtilLauncher(id);
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

        // GET api/launchers/regsvr32/{id}
        // <summary>
        // Get a Regsvr32Launcher
        // </summary>
        [HttpGet("regsvr32/{id}", Name = "GetRegsvr32Launcher")]
        public async Task<ActionResult<Regsvr32Launcher>> GetRegsvr32Launcher(int id)
        {
            try
            {
                return await _service.GetRegsvr32Launcher(id);
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

        // GET api/launchers/mshta/{id}
        // <summary>
        // Get a MshtaLauncher
        // </summary>
        [HttpGet("mshta/{id}", Name = "GetMshtaLauncher")]
        public async Task<ActionResult<MshtaLauncher>> GetMshtaLauncher(int id)
        {
            try
            {
                return await _service.GetMshtaLauncher(id);
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

        // POST api/launchers/binary
        // <summary>
        // Create BinaryLauncher
        // </summary>
        [HttpPost("binary", Name = "CreateBinaryLauncher")]
        public async Task<ActionResult<BinaryLauncher>> CreateBinaryLauncher([FromBody] BinaryLauncher launcher)
        {
            try
            {
                return await _service.CreateBinaryLauncher(launcher);
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

        // POST api/launchers/shellcode
        // <summary>
        // Create ShellCodeLauncher
        // </summary>
        [HttpPost("shellcode", Name = "CreateShellCodeLauncher")]
        public async Task<ActionResult<ShellCodeLauncher>> CreateShellCodeLauncher([FromBody] ShellCodeLauncher launcher)
        {
            try
            {
                return await _service.CreateShellCodeLauncher(launcher);
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

        // POST api/launchers/powershell
        // <summary>
        // Create PowerShellLauncher
        // </summary>
        [HttpPost("powershell", Name = "CreatePowerShellLauncher")]
        public async Task<ActionResult<PowerShellLauncher>> CreatePowerShellLauncher([FromBody] PowerShellLauncher launcher)
        {
            try
            {
                return await _service.CreatePowerShellLauncher(launcher);
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

        // POST api/launchers/msbuild
        // <summary>
        // Create MSBuildLauncher
        // </summary>
        [HttpPost("msbuild", Name = "CreateMSBuildLauncher")]
        public async Task<ActionResult<MSBuildLauncher>> CreateMSBuildLauncher([FromBody] MSBuildLauncher launcher)
        {
            try
            {
                return await _service.CreateMSBuildLauncher(launcher);
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

        // POST api/launchers/installutil
        // <summary>
        // Create InstallUtilLauncher
        // </summary>
        [HttpPost("installutil", Name = "CreateInstallUtilLauncher")]
        public async Task<ActionResult<InstallUtilLauncher>> CreateInstallUtilLauncher([FromBody] InstallUtilLauncher launcher)
        {
            try
            {
                return await _service.CreateInstallUtilLauncher(launcher);
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

        // POST api/launcher/regsvr32
        // <summary>
        // Create Regsvr32Launcher
        // </summary>
        [HttpPost("regsvr32", Name = "CreateRegsvr32Launcher")]
        public async Task<ActionResult<Regsvr32Launcher>> CreateRegsvr32Launcher([FromBody] Regsvr32Launcher launcher)
        {
            try
            {
                return await _service.CreateRegsvr32Launcher(launcher);
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

        // POST api/launchers/mshta
        // <summary>
        // Create MshtaLauncher
        // </summary>
        [HttpPost("mshta", Name = "CreateMshtaLauncher")]
        public async Task<ActionResult<MshtaLauncher>> CreateMshtaLauncher([FromBody] MshtaLauncher launcher)
        {
            try
            {
                return await _service.CreateMshtaLauncher(launcher);
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

        // POST api/launchers/hosted/{id}
        // <summary>
        // Create a launcher that points to a hosted file
        // </summary>
        [HttpPost("hosted/{id}", Name = "CreateHostedLauncher")]
        public async Task<ActionResult<Launcher>> CreateHostedLauncher(int id, [FromBody] HostedFile file)
        {
            try
            {
                return await _service.CreateHostedLauncher(id, file);
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

        // PUT api/launchers/binary
        // <summary>
        // Edit BinaryLauncher
        // </summary>
        [HttpPut("binary", Name = "EditBinaryLauncher")]
        public async Task<ActionResult<BinaryLauncher>> EditBinaryLauncher([FromBody] BinaryLauncher launcher)
        {
            try
            {
                return await _service.EditBinaryLauncher(launcher);
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

        // PUT api/launchers/shellcode
        // <summary>
        // Edit ShellCodeLauncher
        // </summary>
        [HttpPut("shellcode", Name = "EditShellCodeLauncher")]
        public async Task<ActionResult<ShellCodeLauncher>> EditShellCodeLauncher([FromBody] ShellCodeLauncher launcher)
        {
            try
            {
                return await _service.EditShellCodeLauncher(launcher);
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

        // PUT api/launchers/powershell
        // <summary>
        // Edit PowerShellLauncher
        // </summary>
        [HttpPut("powershell", Name = "EditPowerShellLauncher")]
        public async Task<ActionResult<PowerShellLauncher>> EditPowerShellLauncher([FromBody] PowerShellLauncher launcher)
        {
            try
            {
                return await _service.EditPowerShellLauncher(launcher);
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

        // PUT api/launchers/msbuild
        // <summary>
        // Edit MSBuildLauncher
        // </summary>
        [HttpPut("msbuild", Name = "EditMSBuildLauncher")]
        public async Task<ActionResult<MSBuildLauncher>> EditMSBuildLauncher([FromBody] MSBuildLauncher launcher)
        {
            try
            {
                return await _service.EditMSBuildLauncher(launcher);
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

        // PUT api/launchers/installutil
        // <summary>
        // Edit InstallUtilLauncher
        // </summary>
        [HttpPut("installutil", Name = "EditInstallUtilLauncher")]
        public async Task<ActionResult<InstallUtilLauncher>> EditInstallUtilLauncher([FromBody] InstallUtilLauncher launcher)
        {
            try
            {
                return await _service.EditInstallUtilLauncher(launcher);
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

        // PUT api/launchers/regsvr32
        // <summary>
        // Edit Regsvr32Launcher
        // </summary>
        [HttpPut("regsvr32", Name = "EditRegsvr32Launcher")]
        public async Task<ActionResult<Regsvr32Launcher>> EditRegsvr32Launcher([FromBody]Regsvr32Launcher launcher)
        {
            try
            {
                return await _service.EditRegsvr32Launcher(launcher);
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

        // PUT api/launchers/mshta
        // <summary>
        // Edit MshtaLauncher
        // </summary>
        [HttpPut("mshta", Name = "EditMshtaLauncher")]
        public async Task<ActionResult<MshtaLauncher>> EditMshtaLauncher([FromBody] MshtaLauncher launcher)
        {
            try
            {
                return await _service.EditMshtaLauncher(launcher);
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

        // DELETE api/launchers/{id}
        // <summary>
        // Delete a Launcher
        // </summary>
        [HttpDelete("{id}", Name = "DeleteLauncher")]
        [ProducesResponseType(204)]
        public async Task<ActionResult> DeleteLauncher(int id)
        {
            try
            {
                await _service.DeleteLauncher(id);
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

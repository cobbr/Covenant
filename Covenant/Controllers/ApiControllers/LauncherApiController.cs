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
        // Get PowerShellLauncher
        // </summary>
        [HttpGet(Name = "GetLaunchers")]
        public async Task<ActionResult<IEnumerable<Launcher>>> GetLaunchers()
        {
            return Ok(await _service.GetLaunchers());
        }

        // GET api/launchers/binary
        // <summary>
        // Get BinaryLauncher
        // </summary>
        [HttpGet("binary", Name = "GetBinaryLauncher")]
        public async Task<ActionResult<BinaryLauncher>> GetBinaryLauncher()
        {
            try
            {
                return await _service.GetBinaryLauncher();
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
        // Generate BinaryLauncher LauncherString
        // </summary>
        [HttpPost("binary", Name = "GenerateBinaryLauncher")]
        public async Task<ActionResult<BinaryLauncher>> GenerateBinaryLauncher()
        {
            try
            {
                return await _service.GenerateBinaryLauncher();
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

        // POST api/launchers/binary/hosted
        // <summary>
        // Generate a BinaryLauncher that points to a hosted binary file
        // </summary>
        [HttpPost("binary/hosted", Name = "GenerateBinaryHostedLauncher")]
        public async Task<ActionResult<BinaryLauncher>> GenerateBinaryHostedLauncher(HostedFile file)
        {
            try
            {
                return await _service.GenerateBinaryHostedLauncher(file);
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
        public async Task<ActionResult<BinaryLauncher>> EditBinaryLauncher([FromBody]BinaryLauncher launcher)
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

        // GET api/launchers/shellcode
        // <summary>
        // Get ShellCodeLauncher
        // </summary>
        [HttpGet("shellcode", Name = "GetShellCodeLauncher")]
        public async Task<ActionResult<ShellCodeLauncher>> GetShellCodeLauncher()
        {
            try
            {
                return await _service.GetShellCodeLauncher();
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
        // Generate ShellCodeLauncher
        // </summary>
        [HttpPost("shellcode", Name = "GenerateShellCodeLauncher")]
        public async Task<ActionResult<ShellCodeLauncher>> GenerateShellCodeLauncher()
        {
            try
            {
                return await _service.GenerateShellCodeLauncher();
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

        // POST api/launchers/shellcode/hosted
        // <summary>
        // Generate a ShellCodeLauncher that points to a hosted binary file
        // </summary>
        [HttpPost("shellcode/hosted", Name = "GenerateShellCodeHostedLauncher")]
        public async Task<ActionResult<ShellCodeLauncher>> GenerateShellCodeHostedLauncher(HostedFile file)
        {
            try
            {
                return await _service.GenerateShellCodeHostedLauncher(file);
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

        // GET api/launchers/powershell
        // <summary>
        // Get PowerShellLauncher
        // </summary>
        [HttpGet("powershell", Name = "GetPowerShellLauncher")]
        public async Task<ActionResult<PowerShellLauncher>> GetPowerShellLauncher()
        {
            try
            {
                return await _service.GetPowerShellLauncher();
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
        // Generate PowerShellLauncher LauncherString
        // </summary>
        [HttpPost("powershell", Name = "GeneratePowerShellLauncher")]
        public async Task<ActionResult<PowerShellLauncher>> GeneratePowerShellLauncher()
        {
            try
            {
                return await _service.GeneratePowerShellLauncher();
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

        // POST api/launchers/powershell/hosted
        // <summary>
        // Generate a PowerShellLauncher that points to a hosted powershell file
        // </summary>
        [HttpPost("powershell/hosted", Name = "GeneratePowerShellHostedFileLauncher")]
        public async Task<ActionResult<PowerShellLauncher>> GeneratePowerShellHostedFileLauncher(HostedFile file)
        {
            try
            {
                return await _service.GeneratePowerShellHostedLauncher(file);
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

        // GET api/launchers/msbuild
        // <summary>
        // Get MSBuildLauncher
        // </summary>
        [HttpGet("msbuild", Name = "GetMSBuildLauncher")]
        public async Task<ActionResult<MSBuildLauncher>> GetMSBuildLauncher()
        {
            try
            {
                return await _service.GetMSBuildLauncher();
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
        // Generate MSBuild LauncherString
        // </summary>
        [HttpPost("msbuild", Name = "GenerateMSBuildLauncher")]
        public async Task<ActionResult<MSBuildLauncher>> GenerateMSBuildLauncher()
        {
            try
            {
                return await _service.GenerateMSBuildLauncher();
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

        // POST api/launchers/msbuild/hosted
        // <summary>
        // Generate a MSBuildLauncher that points to a hosted msbuild xml file
        // </summary>
        [HttpPost("msbuild/hosted", Name = "GenerateMSBuildHostedFileLauncher")]
        public async Task<ActionResult<MSBuildLauncher>> GenerateMSBuildHostedFileLauncher(HostedFile file)
        {
            try
            {
                return await _service.GenerateMSBuildHostedLauncher(file);
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

        // GET api/launchers/installutil
        // <summary>
        // Get InstallUtilLauncher
        // </summary>
        [HttpGet("installutil", Name = "GetInstallUtilLauncher")]
        public async Task<ActionResult<InstallUtilLauncher>> GetInstallUtilLauncher()
        {
            try
            {
                return await _service.GetInstallUtilLauncher();
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
        // Generate InstallUtil LauncherString
        // </summary>
        [HttpPost("installutil", Name = "GenerateInstallUtilLauncher")]
        public async Task<ActionResult<InstallUtilLauncher>> GenerateInstallUtilLauncher()
        {
            try
            {
                return await _service.GenerateInstallUtilLauncher();
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

        // POST api/launchers/installutil/hosted
        // <summary>
        // Generate a InstallUtilLauncher that points to a hosted msbuild xml file
        // </summary>
        [HttpPost("installutil/hosted", Name = "GenerateInstallUtilHostedFileLauncher")]
        public async Task<ActionResult<InstallUtilLauncher>> GenerateInstallUtilHostedFileLauncher(HostedFile file)
        {
            try
            {
                return await _service.GenerateInstallUtilHostedLauncher(file);
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

        // GET api/launchers/wmic
        // <summary>
        // Get WmicLauncher
        // </summary>
        [HttpGet("wmic", Name = "GetWmicLauncher")]
        public async Task<ActionResult<WmicLauncher>> GetWmicLauncher()
        {
            try
            {
                return await _service.GetWmicLauncher();
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

        // POST api/launchers/wmic
        // <summary>
        // Generate WmicLauncher LauncherString
        // </summary>
        [HttpPost("wmic", Name = "GenerateWmicLauncher")]
        public async Task<ActionResult<WmicLauncher>> GenerateWmicLauncher()
        {
            try
            {
                return await _service.GenerateWmicLauncher();
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

        // POST api/launchers/wmic/hosted
        // <summary>
        // Generate a WmicLauncher that points to a hosted xls file
        // </summary>
        [HttpPost("wmic/hosted", Name = "GenerateWmicHostedFileLauncher")]
        public async Task<ActionResult<WmicLauncher>> GenerateWmicHostedFileLauncher(HostedFile file)
        {
            try
            {
                return await _service.GenerateWmicHostedLauncher(file);
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

        // PUT api/launchers/wmic
        // <summary>
        // Edit WmicLauncher
        // </summary>
        [HttpPut("wmic", Name = "EditWmicLauncher")]
        public async Task<ActionResult<WmicLauncher>> EditWmicLauncher([FromBody]WmicLauncher launcher)
        {
            try
            {
                return await _service.EditWmicLauncher(launcher);
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
        // Get Regsvr32Launcher
        // </summary>
        [HttpGet("regsvr32", Name = "GetRegsvr32Launcher")]
        public async Task<ActionResult<Regsvr32Launcher>> GetRegsvr32Launcher()
        {
            try
            {
                return await _service.GetRegsvr32Launcher();
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
        // Generate Regsvr32Launcher LauncherString
        // </summary>
        [HttpPost("regsvr32", Name = "GenerateRegsvr32Launcher")]
        public async Task<ActionResult<Regsvr32Launcher>> GenerateRegsvr32Launcher()
        {
            try
            {
                return await _service.GenerateRegsvr32Launcher();
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

        // POST api/launchers/regsvr32/hosted
        // <summary>
        // Generate a Regsvr32Launcher that points to a hosted sct file
        // </summary>
        [HttpPost("regsvr32/hosted", Name = "GenerateRegsvr32HostedFileLauncher")]
        public async Task<ActionResult<Regsvr32Launcher>> GenerateRegsvr32HostedFileLauncher(HostedFile file)
        {
            try
            {
                return await _service.GenerateRegsvr32HostedLauncher(file);
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

        // GET api/launchers/mshta
        // <summary>
        // Get MshtaLauncher
        // </summary>
        [HttpGet("mshta", Name = "GetMshtaLauncher")]
        public async Task<ActionResult<MshtaLauncher>> GetMshtaLauncher()
        {
            try
            {
                return await _service.GetMshtaLauncher();
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
        // Generate MshtaLauncher LauncherString
        // </summary>
        [HttpPost("mshta", Name = "GenerateMshtaLauncher")]
        public async Task<ActionResult<MshtaLauncher>> GenerateMshtaLauncher()
        {
            try
            {
                return await _service.GenerateMshtaLauncher();
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

        // POST api/launchers/mshta/hosted
        // <summary>
        // Generate a MshtaLauncher that points to a hosted sct file
        // </summary>
        [HttpPost("mshta/hosted", Name = "GenerateMshtaHostedFileLauncher")]
        public async Task<ActionResult<MshtaLauncher>> GenerateMshtaHostedFileLauncher(HostedFile file)
        {
            try
            {
                return await _service.GenerateMshtaHostedLauncher(file);
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

        // GET api/launchers/cscript
        // <summary>
        // Get CscriptLauncher
        // </summary>
        [HttpGet("cscript", Name = "GetCscriptLauncher")]
        public async Task<ActionResult<CscriptLauncher>> GetCscriptLauncher()
        {
            try
            {
                return await _service.GetCscriptLauncher();
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

        // POST api/launchers/cscript
        // <summary>
        // Generate CscriptLauncher LauncherString
        // </summary>
        [HttpPost("cscript", Name = "GenerateCscriptLauncher")]
        public async Task<ActionResult<CscriptLauncher>> GenerateCscriptLauncher()
        {
            try
            {
                return await _service.GenerateCscriptLauncher();
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

        // POST api/launchers/cscript/hosted
        // <summary>
        // Generate a CscriptLauncher that points to a hosted sct file
        // </summary>
        [HttpPost("cscript/hosted", Name = "GenerateCscriptHostedFileLauncher")]
        public async Task<ActionResult<CscriptLauncher>> GenerateCscriptHostedFileLauncher(HostedFile file)
        {
            try
            {
                return await _service.GenerateCscriptHostedLauncher(file);
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

        // PUT api/launchers/cscript
        // <summary>
        // Edit CscriptLauncher
        // </summary>
        [HttpPut("cscript", Name = "EditCscriptLauncher")]
        public async Task<ActionResult<CscriptLauncher>> EditCscriptLauncher([FromBody]CscriptLauncher launcher)
        {
            try
            {
                return await _service.EditCscriptLauncher(launcher);
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

        // GET api/launchers/wscript
        // <summary>
        // Get WscriptLauncher
        // </summary>
        [HttpGet("wscript", Name = "GetWscriptLauncher")]
        public async Task<ActionResult<WscriptLauncher>> GetWscriptLauncher()
        {
            try
            {
                return await _service.GetWscriptLauncher();
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

        // POST api/launchers/wscript
        // <summary>
        // Generate WscriptLauncher LauncherString
        // </summary>
        [HttpPost("wscript", Name = "GenerateWscriptLauncher")]
        public async Task<ActionResult<WscriptLauncher>> GenerateWscriptLauncher()
        {
            try
            {
                return await _service.GenerateWscriptLauncher();
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

        // POST api/launchers/wscript/hosted
        // <summary>
        // Generate a WscriptLauncher that points to a hosted sct file
        // </summary>
        [HttpPost("wscript/hosted", Name = "GenerateWscriptHostedFileLauncher")]
        public async Task<ActionResult<WscriptLauncher>> GenerateWscriptHostedFileLauncher(HostedFile file)
        {
            try
            {
                return await _service.GenerateWscriptHostedLauncher(file);
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

        // PUT api/launchers/wscript
        // <summary>
        // Edit WscriptLauncher
        // </summary>
        [HttpPut("wscript", Name = "EditWscriptLauncher")]
        public async Task<ActionResult<WscriptLauncher>> EditWscriptLauncher([FromBody] WscriptLauncher launcher)
        {
            try
            {
                return await _service.EditWscriptLauncher(launcher);
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

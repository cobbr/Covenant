using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using Covenant.Models.Covenant;

namespace Covenant.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<CovenantUser> _signInManager;

        public LogoutModel(SignInManager<CovenantUser> signInManager)
        {
            _signInManager = signInManager;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            await _signInManager.SignOutAsync();
            return LocalRedirect("/covenantuser/login");
        }
    }
}

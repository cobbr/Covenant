using Microsoft.AspNetCore.Components;

using Covenant.Core;

namespace Covenant.Components
{
    public class CovenantServiceComponentBase : ComponentBase
    {
        [Inject]
        private ICovenantService _ICovenantService { get; set; }
        private object _ICovenantServiceLock = new object();
        protected ICovenantService ICovenantService {
            get
            {
                return _ICovenantService;
            }
        }
    }
}

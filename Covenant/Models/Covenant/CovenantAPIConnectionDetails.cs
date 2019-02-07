// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Covenant.Models.Covenant
{
    public class CovenantAPIConnectionDetails
    {
        public int Id { get; set; } = 1;
        public String CovenantURI { get; set; }
        public String token { get; set; }
    }
}

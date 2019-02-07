// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Collections.Generic;

namespace Covenant.Core
{
    public class CovenantException: Exception
    {
        public CovenantException() : base()
        {

        }
        public CovenantException(string message) : base(message)
        {

        }
    }

    public class CovenantDirectoryTraversalException : Exception
    {
        public CovenantDirectoryTraversalException() : base()
        {

        }
        public CovenantDirectoryTraversalException(string message) : base(message)
        {

        }
    }

    public class CovenantLauncherNeedsListenerException : CovenantException
    {
        public CovenantLauncherNeedsListenerException() : base()
        {

        }
        public CovenantLauncherNeedsListenerException(string message) : base(message)
        {

        }
    }

    public class CovenantCompileGruntStagerFailedException : CovenantException
    {
        public CovenantCompileGruntStagerFailedException() : base()
        {

        }
        public CovenantCompileGruntStagerFailedException(string message) : base(message)
        {

        }
    }
}

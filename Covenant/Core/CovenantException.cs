// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Collections.Generic;

namespace Covenant.Core
{
    public class CovenantException : Exception
    {
        public CovenantException() : base()
        {

        }
        public CovenantException(string message) : base(message)
        {

        }
    }

    public class ControllerException : Exception
    {
        public ControllerException() : base()
        {

        }
        public ControllerException(string message) : base(message)
        {

        }
    }

    public class ControllerNotFoundException : Exception
    {
        public ControllerNotFoundException() : base()
        {

        }
        public ControllerNotFoundException(string message) : base(message)
        {

        }
    }

    public class ControllerBadRequestException : Exception
    {
        public ControllerBadRequestException() : base()
        {

        }
        public ControllerBadRequestException(string message) : base(message)
        {

        }
    }

    public class ControllerUnauthorizedException : Exception
    {
        public ControllerUnauthorizedException() : base()
        {

        }
        public ControllerUnauthorizedException(string message) : base(message)
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

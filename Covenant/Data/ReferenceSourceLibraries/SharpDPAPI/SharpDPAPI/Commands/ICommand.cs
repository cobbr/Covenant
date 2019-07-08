using System.Collections.Generic;

namespace SharpDPAPI.Commands
{
    public interface ICommand
    {
        void Execute(Dictionary<string, string> arguments);
    }
}
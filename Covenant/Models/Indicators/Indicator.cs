using Covenant.Core;
using NLog;
using System;
using System.Threading.Tasks;

namespace Covenant.Models.Indicators
{
    public enum IndicatorType
    {
        FileIndicator,
        NetworkIndicator,
        TargetIndicator
    }

    public class Indicator
    {
        public int Id { get; set; }
        public IndicatorType Type { get; set; }
    }

    public class FileIndicator : Indicator, ILoggable
    {
        public string FileName { get; set; } = "";
        public string FilePath { get; set; } = "";

        public string SHA2 { get; set; } = "";
        public string SHA1 { get; set; } = "";
        public string MD5 { get; set; } = "";

        public FileIndicator()
        {
            this.Type = IndicatorType.FileIndicator;
        }

        public override string ToString()
        {
            string output = "";
            if (FileName != "") { output += FileName; }
            if (FilePath != "") { output += FilePath; }
            if (SHA2 != "") { output += SHA2; }
            if (SHA1 != "") { output += SHA1; }
            if (MD5 != "") { output += MD5; }

            return output;
        }

        // FileIndicator|Action|ID|FileName|FilePath|SHA2|SHA1|MD5
        public string ToLog(LogAction action) => $"FileIndicator|{action}|{this.Id}|{this.FileName}|{this.FilePath}|{this.SHA2}|{this.SHA1}|{this.MD5}";
    }

    public class NetworkIndicator : Indicator, ILoggable
    {
        public string Protocol { get; set; } = "";
        public string Domain { get; set; } = "";
        public string IPAddress { get; set; } = "";
        public int Port { get; set; } = 0;
        public string URI { get; set; } = "";

        public NetworkIndicator()
        {
            this.Type = IndicatorType.NetworkIndicator;
        }

        public override string ToString()
        {
            string output = "";
            if (Protocol != "") { output += Protocol; }
            if (Domain != "") { output += Domain; }
            if (IPAddress != "") { output += IPAddress; }
            if (Port != 0) { output += Port; }
            if (URI != "") { output += URI; }

            return output;
        }

        // NetworkIndicator|Action|ID|Protocol|Domain|IPAddress|Port|URI
        public string ToLog(LogAction action) => $"NetworkIndicator|{action}|{this.Id}|{this.Protocol}|{this.Domain}|{this.IPAddress}|{this.Port}|{this.URI}";
    }

    public class TargetIndicator : Indicator, ILoggable
    {
        public string ComputerName { get; set; } = "";
        public string UserName { get; set; } = "";

        public TargetIndicator()
        {
            this.Type = IndicatorType.TargetIndicator;
        }

        public override string ToString()
        {
            string output = "";
            if (ComputerName != "") { output += ComputerName; }
            if (UserName != "") { output += UserName; }

            return output;
        }

        // TargetIndicator|Action|ID|ComputerName|UserName
        public string ToLog(LogAction action) => $"TargetIndicator|{action}|{this.Id}|{this.ComputerName}|{this.UserName}";
    }
}

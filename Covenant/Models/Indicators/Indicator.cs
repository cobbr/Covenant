using System;

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

    public class FileIndicator : Indicator
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
    }

    public class NetworkIndicator : Indicator
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
    }

    public class TargetIndicator : Indicator
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
    }
}

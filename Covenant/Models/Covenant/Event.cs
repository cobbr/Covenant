// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;

using Covenant.Core;

namespace Covenant.Models.Covenant
{
    public enum EventLevel
    {
        Silent,
        Info,
        Warning,
        Highlight,
        Error
    }

    public enum EventType
    {
        Normal,
        Download,
        Screenshot
    }

    public class Event
    {
        public int Id { get; set; }
        public DateTime Time { get; set; } = DateTime.UtcNow;
        public string MessageHeader { get; set; }
        public string MessageBody { get; set; }
        public EventLevel Level { get; set; } = EventLevel.Highlight;
        public EventType Type { get; set; } = EventType.Normal;
		public string Context { get; set; } = "*";
    }

    public class DownloadEvent : Event
    {
        public enum DownloadProgress
        {
            Portion,
            Complete
        }

        public string FileName { get; set; } = "";
        public string FileContents { get; set; } = "";
        public DownloadProgress Progress { get; set; } = DownloadProgress.Portion;

        public DownloadEvent()
        {
            this.Type = EventType.Download;
        }

        public bool WriteToDisk()
        {
            try
            {
                byte[] contents = Convert.FromBase64String(this.FileContents);
                if (this.Progress == DownloadProgress.Complete)
                {
                    File.WriteAllBytes(
                        Path.Combine(Common.CovenantDownloadDirectory, Utilities.GetSanitizedFilename(this.FileName)),
                        contents
                    );
                }
                else
                {
                    using (var stream = new FileStream(Path.Combine(Common.CovenantDownloadDirectory, Utilities.GetSanitizedFilename(this.FileName)), FileMode.Append))
                    {
                        stream.Write(contents, 0, contents.Length);
                    }
                }
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }

    public class ScreenshotEvent : DownloadEvent
    {
        public ScreenshotEvent()
        {
            this.Type = EventType.Screenshot;
        }
    }
}

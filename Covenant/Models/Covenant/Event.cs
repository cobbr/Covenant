// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

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

    public class Event : ILoggable
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; } = Utilities.CreateShortGuid();
        public DateTime Time { get; set; } = DateTime.UtcNow;
        public string MessageHeader { get; set; }
        public string MessageBody { get; set; }
        public EventLevel Level { get; set; } = EventLevel.Highlight;
        public EventType Type { get; set; } = EventType.Normal;
		public string Context { get; set; } = "*";

        // Event|Action|ID|Time|Level|Type|Context|MessageHeader
        public string ToLog(LogAction action) => $"Event|{action}|{this.Id}|{this.Time}|{this.Level}|{this.Type}|{this.Context}|{this.MessageHeader}";
    }

    public class DownloadEvent : Event
    {
        public enum DownloadProgress
        {
            Portion,
            Complete
        }

        public int GruntCommandId { get; set; }
        public DownloadProgress Progress { get; set; } = DownloadProgress.Portion;
        public string FileName { get; set; } = "";
        public long FileLength
        {
            get
            {
                return File.Exists(FileLocation) ? new FileInfo(this.FileLocation).Length : 0;
            }
        }
        private string FileLocation
        {
            get
            {
                return Path.Combine(Common.CovenantDownloadDirectory, Utilities.GetSanitizedFilename(this.Name));
            }
        }

        public DownloadEvent()
        {
            this.Type = EventType.Download;
        }

        public bool WriteDownload(byte[] contents)
        {
            try
            {
                using FileStream stream = new FileStream(this.FileLocation, FileMode.Append);
                stream.Write(contents, 0, contents.Length);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public FileStream ReadDownload()
        {
            if (File.Exists(this.FileLocation))
            {
                return new FileStream(this.FileLocation, FileMode.Open);
            }
            return null;
        }
    }

    public class ScreenshotEvent : DownloadEvent
    {
        public ScreenshotEvent()
        {
            this.Type = EventType.Screenshot;
        }
    }

    public class DownloadEventContent : DownloadEvent
    {
        public byte[] FileContents { get; set; }
    }

    public class ScreenshotEventContent : ScreenshotEvent
    {
        public byte[] FileContents { get; set; }
    }
}

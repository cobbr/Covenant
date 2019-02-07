// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;

namespace Covenant.Models.Covenant
{
    public class Event
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
            Download
        }

        public int Id { get; set; }
        public DateTime Time { get; set; } = DateTime.Now;
        public string Message { get; set; }
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
    }
}

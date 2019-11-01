// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.IO.Compression;

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
            byte[] contents = DecompressGZip(Convert.FromBase64String(this.FileContents));
            this.FileContents = Convert.ToBase64String(contents); // dirty hack
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

        private static byte[] DecompressGZip(byte[] compressedArray)
        {
            using (var gZipStream = new GZipStream(new MemoryStream(compressedArray), CompressionMode.Decompress))
            {
                const int size = 4096;
                var buffer = new byte[size];
                using (var memoryStream = new MemoryStream())
                {
                    var count = 0;
                    do
                    {
                        count = gZipStream.Read(buffer, 0, size);
                        if (count > 0)
                        {
                            memoryStream.Write(buffer, 0, count);
                        }
                    }
                    while (count > 0);
                    return memoryStream.ToArray();
                }
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

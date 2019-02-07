// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;

namespace SharpSploit.Misc
{
    public static class Utilities
    {
        private static string[] manifestResources = Assembly.GetExecutingAssembly().GetManifestResourceNames();

        public static byte[] GetEmbeddedResourceBytes(string resourceName)
        {
            string resourceFullName = manifestResources.FirstOrDefault(N => N.Contains(resourceName + ".comp"));
            if (resourceFullName != null)
            {
                return Decompress(Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceFullName).ReadFully());
            }
            else if ((resourceFullName = manifestResources.FirstOrDefault(N => N.Contains(resourceName))) != null)
            {
                return Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceFullName).ReadFully();
            }
            return null;
        }

        public static byte[] ReadFully(this Stream input)
        {
            byte[] buffer = new byte[16 * 1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }

        public static byte[] Compress(byte[] Bytes)
        {
            byte[] compressedBytes;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (DeflateStream deflateStream = new DeflateStream(memoryStream, CompressionMode.Compress))
                {
                    deflateStream.Write(Bytes, 0, Bytes.Length);
                }
                compressedBytes = memoryStream.ToArray();
            }
            return compressedBytes;
        }

        public static byte[] Decompress(byte[] compressed)
        {
            using (MemoryStream inputStream = new MemoryStream(compressed.Length))
            {
                inputStream.Write(compressed, 0, compressed.Length);
                inputStream.Seek(0, SeekOrigin.Begin);
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (DeflateStream deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = deflateStream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            outputStream.Write(buffer, 0, bytesRead);
                        }
                    }
                    return outputStream.ToArray();
                }
            }
        }
    }
}

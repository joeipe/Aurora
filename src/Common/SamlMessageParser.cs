using System;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace Common
{
    public interface ISamlMessageParser
    {
        Task<string> ParseSamlMessage(string message);
    }

    public class SamlMessageParser : ISamlMessageParser
    {
        public async Task<string> ParseSamlMessage(string message)
        {
            if (string.IsNullOrWhiteSpace(message)) return null;

            string formattedMessage;
            formattedMessage = message.TrimStart('=', '?').TrimEnd('&');

            // handle plain XML
            if (formattedMessage.StartsWith('<') && formattedMessage.EndsWith('>')) return FormatXml(formattedMessage);

            // URL decode
            formattedMessage = UrlDecode(formattedMessage);

            // deflate or base64 decoe
            formattedMessage = await DecodeAndDecompress(formattedMessage);

            // format
            formattedMessage = FormatXml(formattedMessage);

            return formattedMessage;
        }

        private string UrlDecode(string message)
        {
            if (message.Contains("%"))
                return WebUtility.UrlDecode(message);

            return message;
        }

        private async Task<string> DecodeAndDecompress(string message)
        {
            try
            {
                using (var outputStream = new MemoryStream())
                using (var compressedStream = new MemoryStream(Convert.FromBase64String(message)))
                using (var deflateStream = new DeflateStream(compressedStream, CompressionMode.Decompress))
                {
                    await deflateStream.CopyToAsync(outputStream);
                    var array = outputStream.ToArray();
                    return Encoding.UTF8.GetString(array);
                }
            }
            catch
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(message));
            }
        }

        private string FormatXml(string message)
        {
            var stringBuilder = new StringBuilder();
            var element = XElement.Parse(message);

            var settings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true,
                Indent = true,
                NewLineOnAttributes = true
            };

            using (var xmlWriter = XmlWriter.Create(stringBuilder, settings))
            {
                element.Save(xmlWriter);
            }

            return stringBuilder.ToString();
        }
    }
}

using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace davidsp8.common.Security.Saml
{
    public static class EncryptionHelper
    {
        /// <summary>
        /// Signs an XML Document for a Saml Response
        /// </summary>
        /// <param name="xml"></param>
        /// <param name="cert2"></param>
        /// <param name="referenceId"></param>
        /// <returns></returns>
        public static EncryptedData EncryptDoc(XmlDocument doc, X509Certificate2 cert2)
        {
            EncryptedXml xml = new EncryptedXml(doc);
            return xml.Encrypt(doc.DocumentElement, cert2);

        }
    }
}

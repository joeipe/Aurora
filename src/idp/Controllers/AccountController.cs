using Common;
using davidsp8.common.Security.Saml20;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace idp.Controllers
{
    //[Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly ISamlMessageParser samlMessageParser;

        public AccountController(
            ISamlMessageParser samlMessageParser)
        {
            this.samlMessageParser = samlMessageParser ?? throw new ArgumentNullException(nameof(samlMessageParser));
        }

        [Route("saml/sso")]
        [HttpGet]
        public async Task<ActionResult> Login(string samlRequest, string relayState)
        {
            var request = await samlMessageParser.ParseSamlMessage(samlRequest);

            //var responseEncoded = GetSAMLResponse(request);
            var responseEncoded = GetSAMLResponse2(request);
            var response = await samlMessageParser.ParseSamlMessage(responseEncoded);

            /*
            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri("https://localhost:5001");
                client.DefaultRequestHeaders.Accept.Clear();

                var multiContent = new MultipartFormDataContent();

                multiContent.Add(new StringContent(responseEncoded), "SAMLResponse");
                multiContent.Add(new StringContent(relayState), "RelayState");

                var result = await client.PostAsync("/saml/acs", multiContent);
                if (result.IsSuccessStatusCode)
                {
                    var resultContent = await result.Content.ReadAsStringAsync();
                    return Ok(resultContent);
                    //return Redirect($"https://localhost:5001/saml/acs?SAMLResponse={responseEncoded}&RelayState={relayState}");
                }
            }
            */


            var url = "https://localhost:5001/saml/acs";
            var nvc = new List<KeyValuePair<string, string>>();
            nvc.Add(new KeyValuePair<string, string>("SAMLResponse", responseEncoded));
            nvc.Add(new KeyValuePair<string, string>("RelayState", relayState));
            var client = new HttpClient();
            var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new FormUrlEncodedContent(nvc) };
            client.DefaultRequestHeaders.Add("Connection", "keep-alive");
            client.DefaultRequestHeaders.Add("Cache-Control", "max-age=0");
            client.DefaultRequestHeaders.Add("sec-ch-ua", "\"Chromium\";v=\"92\", \" Not A; Brand\";v=\"99\", \"Google Chrome\";v=\"92\"");
            client.DefaultRequestHeaders.Add("sec-ch-ua-mobile", "?0");
            client.DefaultRequestHeaders.Add("Upgrade-Insecure-Requests", "1");
            client.DefaultRequestHeaders.Add("Origin", "https://localhost:44321");
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36");
            client.DefaultRequestHeaders.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
            client.DefaultRequestHeaders.Add("Sec-Fetch-Site", "same-site");
            client.DefaultRequestHeaders.Add("Sec-Fetch-Mode", "navigate");
            client.DefaultRequestHeaders.Add("Sec-Fetch-Dest", "document");
            client.DefaultRequestHeaders.Add("Referer", "https://localhost:44321/");
            client.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate, br");
            client.DefaultRequestHeaders.Add("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8");
            var res = await client.SendAsync(req);
            if (res.IsSuccessStatusCode)
            {
                var resultContent = await res.Content.ReadAsStringAsync();
                return Ok(resultContent);
            }

            //{
            //    var postbackUrl = "https://localhost:5001/saml/acs";

            //    StringBuilder sb = new StringBuilder();
            //    sb.Append("<html>");
            //    sb.AppendFormat(@"<body onload='document.forms[""form""].submit()'>");
            //    sb.AppendFormat("<form name='form' action='{0}' method='post'>", postbackUrl);
            //    sb.AppendFormat("<input type='hidden' name='SAMLResponse' value='{0}'>", responseEncoded);
            //    sb.AppendFormat("<input type='hidden' name='RelayState' value='{0}'>", relayState);
            //    sb.Append("</form>");
            //    sb.Append("</body>");
            //    sb.Append("</html>");

            //    return Ok(sb.ToString());
            //}

            return Ok();
        }

        private string GetSAMLResponse(string request)
        {
            var retVal = "";

            string inResponseTo = "";
            {
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(request);
                //string xpath = "saml2p:AuthnRequest";
                //var nodes = xmlDoc.SelectNodes(xpath);
                var node = xmlDoc.FirstChild;
                inResponseTo = node.Attributes["ID"].Value;
            }

            // Set Attrs
            Dictionary<string, string> attrs = new Dictionary<string, string>();
            attrs.Add("" +
                "Name", "Joe".ToString());

            retVal =
                SamlHelper.GetPostSamlResponse(
                inResponseTo,
                "https://localhost:5001/saml/acs",
                "https://localhost:44321",
                "https://localhost:5001",
                "localuserid",
                StoreLocation.LocalMachine, StoreName.Root, X509FindType.FindByThumbprint, "joeidp.pfx", "joe",
                "", attrs);

            return retVal;
        }

        private string GetSAMLResponse2(string request)
        {
            var retVal = "";

            string inResponseTo = "";
            {
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(request);
                //string xpath = "saml2p:AuthnRequest";
                //var nodes = xmlDoc.SelectNodes(xpath);
                var node = xmlDoc.FirstChild;
                inResponseTo = node.Attributes["ID"].Value;
            }

            var replace_responseId = "_" + Guid.NewGuid().ToString();
            var replace_inResponseTo = inResponseTo;
            var replace_audience = "https://localhost:5001";
            var replace_destination = "https://localhost:5001/saml/acs";
            var replace_issuer = "https://localhost:44321";
            var replace_issueInstant = DateTime.UtcNow.ToString("s") + "Z";
            var replace_issueNotOnOrAfter = DateTime.UtcNow.AddDays(100).ToString("s") + "Z";

            var requestStr = $"<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{replace_responseId}\" Version=\"2.0\" IssueInstant=\"{replace_issueInstant}\" Destination=\"{replace_destination}\" InResponseTo=\"{replace_inResponseTo}\"><saml2:Issuer>{replace_issuer}</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></saml2p:Status><saml2:Assertion ID=\"_55387a4a-5bab-4de6-8391-e0dff23aabf8\" Version=\"2.0\" IssueInstant=\"{replace_issueInstant}\"><saml2:Issuer>{replace_issuer}</saml2:Issuer><saml2:Subject><saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">1</saml2:NameID><saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml2:SubjectConfirmationData NotOnOrAfter=\"{replace_issueNotOnOrAfter}\" InResponseTo=\"{replace_inResponseTo}\" Recipient=\"{replace_destination}\" /></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore=\"{replace_issueInstant}\" NotOnOrAfter=\"{replace_issueNotOnOrAfter}\"><saml2:AudienceRestriction><saml2:Audience>{replace_audience}</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AttributeStatement><saml2:Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\"><saml2:AttributeValue>Joe</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement><saml2:AuthnStatement AuthnInstant=\"{replace_issueInstant}\" SessionIndex=\"_55387a4a-5bab-4de6-8391-e0dff23aabf8\"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>";

            retVal = SamlHelper.GetPostSamlResponse2(requestStr, replace_responseId, StoreLocation.LocalMachine, StoreName.Root, X509FindType.FindByThumbprint, "joeidp.pfx", "joe", "");

            return retVal;
        }
    }
}

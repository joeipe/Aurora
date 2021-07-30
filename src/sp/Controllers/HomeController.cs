using System;
using System.Threading.Tasks;
using Common;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace sp.Controllers
{
    public class HomeController : Controller
    {
        private readonly ISamlMessageParser messageParser;
        private readonly SamlMessageStore messageStore;

        public HomeController(ISamlMessageParser messageParser, SamlMessageStore messageStore)
        {
            this.messageParser = messageParser ?? throw new ArgumentNullException(nameof(messageParser));
            this.messageStore = messageStore ?? throw new ArgumentNullException(nameof(messageStore));
        }

        public async Task<IActionResult> Index()
        {
            var saml = await messageParser.ParseSamlMessage(messageStore.CurrentMessage);
            return View(new ViewModel { SamlMessage = await messageParser.ParseSamlMessage(messageStore.CurrentMessage) });
        }

        public IActionResult Login() => Challenge(new AuthenticationProperties {RedirectUri = "/home"}, "saml");
    }

    public class ViewModel
    {
        public string SamlMessage { get; set; }
    }
}

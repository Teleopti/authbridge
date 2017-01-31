using NUnit.Framework;

namespace AuthBridge.Web.Tests
{
    using System;
    using System.Web;
    using System.Web.Mvc;
    using Moq;

    using Controllers;
    using Services;

    using Configuration;
    using Model;
    using Protocols;

	[TestFixture]
	public class AuthenticationControllerFixture
    {
        [Test]
        public void ShouldRenderTheIdentityProviderSelectorViewWhenNoIdentityProviderIdentifierProvided()
        {
            var protocolHandler = new Mock<IProtocolHandler>();
            var defaultProtocolDiscovery = new Mock<IProtocolDiscovery>();
            var federationContext = new Mock<IFederationContext>();
            var configuration = new Mock<IConfigurationRepository>();

            defaultProtocolDiscovery.Setup(s => s.RetrieveProtocolHandler(It.IsAny<ClaimProvider>()))
                .Returns(() => protocolHandler.Object);

            var controller = new AuthenticationController(defaultProtocolDiscovery.Object, federationContext.Object, configuration.Object);

            controller.SetFakeControllerContext();
            controller.Request.SetupRequestUrl("https://somedomain.com/?wa=wsignin1.0&wtrealm=blah&wctx=em");
            controller.HttpContext.SetAnonymousUser();

            var result = controller.ProcessFederationRequest();

            protocolHandler.Verify(p => p.ProcessSignInRequest(It.IsAny<Scope>(), It.IsAny<HttpContextBase>()), Times.Never());
            Assert.IsNotNull(result);
            Assert.AreEqual("Authenticate", ((ViewResult)result).ViewName);
            Assert.IsInstanceOf<HrdViewModel>(((ViewResult)result).Model);
        }

        [Test]
        public void ShouldProcessSignInRequestWhenIdentityProviderIsProvided()
        {
            var protocolHandler = new Mock<IProtocolHandler>();
            var defaultProtocolDiscovery = new Mock<IProtocolDiscovery>();
            var federationContext = new Mock<IFederationContext>();
            var configuration = new Mock<IConfigurationRepository>();

            defaultProtocolDiscovery.Setup(s => s.RetrieveProtocolHandler(It.IsAny<ClaimProvider>()))
                .Returns(() => protocolHandler.Object);

            configuration.Setup(c => c.RetrieveIssuer(It.IsAny<Uri>()))
                .Returns(() => new ClaimProvider { 
                                    Identifier = new Uri("https://identifier"), 
                                    Url = new Uri("https://url")
                });
            configuration.Setup(c => c.RetrieveScope(It.IsAny<Uri>()))
                .Returns(() => new Scope
                {
                    Identifier = new Uri("https://relyingPartyIdentifier"),
                    Url = new Uri("https://url")
                });

            var controller = new AuthenticationController(defaultProtocolDiscovery.Object, federationContext.Object, configuration.Object);

            federationContext.SetupGet(s => s.Realm).Returns("https://relyingPartyIdentifier");
            federationContext.SetupGet(s => s.OriginalUrl).Returns("https://originalUrl");

            controller.SetFakeControllerContext();
            controller.Request.SetupRequestUrl("https://somedomain.com/?wa=wsignin1.0&wtrealm=blah&whr=https://identifier");

            controller.Authenticate();

            protocolHandler.Verify(
                p =>
                p.ProcessSignInRequest(
                    It.Is<Scope>(s => s.Identifier == new Uri("https://relyingPartyIdentifier")), It.IsAny<HttpContextBase>()),
                Times.Once());
        }        
    }
}

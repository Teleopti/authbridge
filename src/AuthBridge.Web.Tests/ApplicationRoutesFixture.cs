using NUnit.Framework;

namespace AuthBridge.Web.Tests
{
    using System.Web;
    using System.Web.Routing;
    using Moq;
	
    public class ApplicationRoutesFixture
    {
        [Test]
        public void ShouldRouteToTheAuthenticationAction()
        {
            var routes = new RouteCollection();
            MvcApplication.RegisterRoutes(routes);

            var httpContextMock = new Mock<HttpContextBase>();
            httpContextMock.Setup(c => c.Request.AppRelativeCurrentExecutionFilePath)
                           .Returns("~/");

            var routeData = routes.GetRouteData(httpContextMock.Object);
            Assert.IsNotNull(routeData);
            Assert.AreEqual("Authentication", routeData.Values["Controller"]);
            Assert.AreEqual("ProcessFederationRequest", routeData.Values["Action"]);
        }

        [Test]
        public void ShouldRouteToTheAuthenticateAction()
        {
            var routes = new RouteCollection();
            MvcApplication.RegisterRoutes(routes);

            var httpContextMock = new Mock<HttpContextBase>();
            httpContextMock.Setup(c => c.Request.AppRelativeCurrentExecutionFilePath)
                           .Returns("~/authenticate");

            var routeData = routes.GetRouteData(httpContextMock.Object);
            Assert.IsNotNull(routeData);
            Assert.AreEqual("Authentication", routeData.Values["Controller"]);
            Assert.AreEqual("Authenticate", routeData.Values["Action"]);
        }

        [Test]
        public void ShouldRouteToTheProcessResponseAction()
        {
            var routes = new RouteCollection();
            MvcApplication.RegisterRoutes(routes);

            var httpContextMock = new Mock<HttpContextBase>();
            httpContextMock.Setup(c => c.Request.AppRelativeCurrentExecutionFilePath)
                           .Returns("~/response");

            var routeData = routes.GetRouteData(httpContextMock.Object);
            Assert.IsNotNull(routeData);
            Assert.AreEqual("Authentication", routeData.Values["Controller"]);
            Assert.AreEqual("ProcessResponse", routeData.Values["Action"]);
        }
    }
}

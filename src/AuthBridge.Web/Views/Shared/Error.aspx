<%@ Page Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage<System.Web.Mvc.HandleErrorInfo>" %>
<%@ Import Namespace="System.IdentityModel.Services.Configuration" %>
<%@ Import Namespace="AuthBridge.Configuration" %>


<script runat="server">

    protected void Page_Load(object sender, EventArgs e)
    {
        var ex = ViewData.Model.Exception;
        if (Request.IsLocal)
            exTrace.Visible = true;
        exMessage.Text = ex.Message;
        exTrace.Text = ex.StackTrace;

        returnToScopeApplication(ex);
    }

    private void returnToScopeApplication(Exception exception)
    {
        var configuration = ConfigurationManager.GetSection("authBridge/multiProtocolIssuer") as MultiProtocolIssuerSection;
        var identityModelServicesSection = ConfigurationManager.GetSection("system.identityModel.services") as SystemIdentityModelServicesSection ;
        if (identityModelServicesSection != null)
        {
            var service = identityModelServicesSection.FederationConfigurationElements.OfType<FederationConfigurationElement>().FirstOrDefault();
            if (service != null)
            {
                var wsFederation = service.WsFederation;
                if (wsFederation != null)
                {
                    clearFederationContext();
                    Response.Redirect(wsFederation.Issuer + "?wa=wsignin1.0&wtrealm=" + wsFederation.Realm + "&wctx=ru%3d" + wsFederation.SignOutReply +"%26em%3d" + HttpUtility.UrlEncode(exMessage.Text), true);
                }
            }
        }
    }

    private void clearFederationContext()
    {
        if (Request.Cookies["FederationContext"] != null)
        {
            HttpCookie myCookie = new HttpCookie("FederationContext");
            myCookie.Expires = DateTime.Now.AddDays(-1d);
            Response.Cookies.Add(myCookie);
        }
    }

</script>

<asp:Content ID="errorTitle" ContentPlaceHolderID="TitleContent" runat="server">
	Error
</asp:Content>

<asp:Content ID="errorContent" ContentPlaceHolderID="MainContent" runat="server">
	<div class="app-title">Teleopti WFM</div>
	<div class="alert alert-danger" style="max-width: 300px; margin-right: auto;margin-left: auto;" role="alert">
		<p><asp:Label ID="exMessage" runat="server" Font-Bold="true" Font-Size="Large" /></p>
	</div>
	<div>
		<asp:Label ID="exTrace" runat="server" Visible="false" />
	</div>
</asp:Content>

<%@ Page Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage<System.Web.Mvc.HandleErrorInfo>" %>
<%@ Import Namespace="AuthBridge.Web.Controllers" %>
<%@ Import Namespace="AuthBridge.Utilities" %>


<script runat="server">

    protected void Page_Load(object sender, EventArgs e)
    {
        var ex = ViewData.Model.Exception;
        if (Request.IsLocal)
            exTrace.Visible = true;
        exMessage.Text = ex.Message;
        exTrace.Text = ex.StackTrace;

        ReturnToScopeApplication(ex);
    }

    private void ReturnToScopeApplication(Exception exception)
    {
        var defaultRedirectUrl = DefaultRedirectUrlProvider.Get();
        if (defaultRedirectUrl != null)
        {
            ClearFederationContext();
            Response.Redirect(defaultRedirectUrl + (string.IsNullOrEmpty(exception.Message) ? "" : "%26em%3d" + HttpUtility.UrlEncode(exception.Message)), true);
        }
    }

    private void ClearFederationContext()
    {
        if (Request.Cookies["FederationContext"] != null)
        {
            var myCookie = new HttpCookie("FederationContext") {Expires = DateTime.Now.AddDays(-1d), HttpOnly = true, Secure = Request.UrlConsideringLoadBalancerHeaders().IsTransportSecure()};
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

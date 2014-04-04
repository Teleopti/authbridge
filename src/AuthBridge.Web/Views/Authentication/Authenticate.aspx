<%@ Page Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage" %>

<asp:Content ID="loginTitle" ContentPlaceHolderID="TitleContent" runat="server">
	AuthBridge
</asp:Content>
<asp:Content ID="loginContent" ContentPlaceHolderID="MainContent" runat="server">
	<div id="selector">
		<form action="" method="get">
			<input type="hidden" name="action" value="verify" />
			<fieldset>
				<legend>Login with one of these identity providers</legend>
				<div>
					<div id="buttons">
						<% if (ViewData["Windows"] != null && (bool)ViewData["Windows"])
		 {    %>
						<a class="windows button"
							href="authenticate?whr=urn:Windows" title="Windows">Windows</a>
						<% } %>
						<% if (ViewData["Teleopti"] != null && (bool)ViewData["Teleopti"])
		 {    %>
						<a class="teleopti button"
							href="authenticate?whr=urn:Teleopti" title="Teleopti">Teleopti</a>
						<% } %>
						<% if (ViewData["Yahoo"] != null && (bool)ViewData["Yahoo"])
		 { %>
						<a class="yahoo button"
							href="authenticate?whr=urn:Yahoo" title="Yahoo"></a>
						<% } %>

						<% if (ViewData["Google"] != null && (bool)ViewData["Google"])
		 { %>
						<a class="google button"
							href="authenticate?whr=urn:Google" title="Google"></a>
						<% } %>
						<% if (ViewData["WindowsLive"] != null && (bool)ViewData["WindowsLive"])
		 { %>
						<a class="liveid button"
							href="authenticate?whr=urn:LiveId" title="Windows Live"></a>
						<% } %>
						<% if (ViewData["Facebook"] != null && (bool)ViewData["Facebook"])
		 { %>
						<a class="facebook button"
							href="authenticate?whr=urn:Facebook" title="Facebook"></a>
						<% } %>
						<% if (ViewData["Twitter"] != null && (bool)ViewData["Twitter"])
		 { %>
						<a class="twitter button"
							href="authenticate?whr=urn:Twitter" title="Twitter"></a>
						<% } %>
						<% if (ViewData["IdentityServer"] != null && (bool)ViewData["IdentityServer"])
		 { %>
						<a class="button"
							href="authenticate?whr=urn:IdentityServer" title="IdentityServer">Identity Server (WS-Fed + SAML)</a>
						<% } %>
						<% if (ViewData["WindowsAzureAD"] != null && (bool)ViewData["WindowsAzureAD"])
		 { %>
						<a class="button"
							href="authenticate?whr=urn:office365:auth10preview" title="WindowsAzure AD">Windows Azure Active Directory (Office 365)</a>
						<% } %>
						<% if (ViewData["SalesForce"] != null && (bool)ViewData["SalesForce"])
		 { %>
						<a class="salesforce button"
							href="authenticate?whr=urn:SalesForce" title="SalesForce">SalesForce</a>
						<% } %>
						<% if (ViewData["MyOpenId"] != null && (bool)ViewData["MyOpenId"])
		 { %>
						<a class="myopenid button"
							href="authenticate?whr=urn:MyOpenId" title="MyOpenId">MyOpenId</a>
						<% } %>
					</div>
				</div>
			</fieldset>
			<input type="hidden" value="<%=HttpContext.Current.Request.QueryString["ReturnUrl"] %>" />
		</form>
	</div>
</asp:Content>
<asp:Content ID="pageSpecificScripts" ContentPlaceHolderID="PageSpecificScripts"
	runat="server">
</asp:Content>

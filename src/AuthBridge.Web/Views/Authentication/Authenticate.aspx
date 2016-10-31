<%@ Page Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage<AuthBridge.Web.Controllers.HrdViewModel>" %>

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
                        <% foreach (var provider in Model.Providers)
                            { %>
                        <a class="<%= provider.Identifier.Replace("urn:","").ToLowerInvariant() %> button"
                            href="authenticate?whr=<%= provider.Identifier %>" title="<%= provider.DisplayName %>"><%= provider.DisplayName %></a>
                        <% }
                        %>
                    </div>
                </div>
            </fieldset>
            <input type="hidden" value="<%=HttpContext.Current.Request.QueryString["ReturnUrl"] %>" />
        </form>
    </div>
    <div>
        <% if (!string.IsNullOrEmpty(Model.ErrorMessage))
            { %>
        <p><%="Warning: " + Model.ErrorMessage%></p>
        <% } %>
    </div>
</asp:Content>
<asp:Content ID="pageSpecificScripts" ContentPlaceHolderID="PageSpecificScripts"
    runat="server">
</asp:Content>

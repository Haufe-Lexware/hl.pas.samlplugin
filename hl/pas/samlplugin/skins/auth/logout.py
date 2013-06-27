## Script (Python) "logout"
##title=Logout handler
##parameters=
from Products.CMFCore.utils import getUtilityByInterfaceName

request = context.REQUEST

if 'SAMLResponse' in request.form:
    # Logout Request was sent by SAML2Plugin.resetCredentials; the user is logged of, redirect
    return request.response.redirect('%s/logged_out' % context.portal_url(), lock=True)

if 'SAMLRequest' in request.form:
    # LogoutRequest was sent by IDP
    u = getUtilityByInterfaceName('hl.pas.samlplugin.interfaces.ISAMLLogoutHandler')
    request.SESSION.set('_saml2_stored_url', request['HTTP_REFERER'])
    return u.redirect_logout_request(request)
else:
    u = getUtilityByInterfaceName('hl.pas.samlplugin.interfaces.ISAMLLogoutHandler')
    redir = u.slo(request)
    return request.response.redirect(redir)

if request.has_key('portal_skin'):
   context.portal_skins.clearSkinCookie()
request.RESPONSE.expireCookie('__ac', path='/')
return request.RESPONSE.redirect(request.URL1+'/logged_out')

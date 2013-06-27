from zope.component import getUtility
from zope.publisher.browser import BrowserView
from AccessControl.unauthorized import Unauthorized
from Products.CMFCore.utils import getToolByName
from hl.pas.samlplugin.interfaces import ISAMLSessionCheck

class LoginView(BrowserView):
    """
    working example view that handles redirects after login
    """
    
    def __call__(self):
        """
        SAML2Plugin will rely on the HTTP_REFERER for redirecting.
        Manipulate it beforehand if necessary.
        """
        mtool = getToolByName(self.context, 'portal_membership')
        if not mtool.isAnonymousUser():
            # The user is logged in, but has insufficient permissions.
            # Since he has a valid SSO session, challenge would go on forever if we proceed.
            raise Unauthorized, 'insufficient permissions'
        came_from = self.request.get('came_from', self.request.HTTP_REFERER)
        self.request.HTTP_REFERER = came_from
        getUtility(ISAMLSessionCheck).active(self.request)


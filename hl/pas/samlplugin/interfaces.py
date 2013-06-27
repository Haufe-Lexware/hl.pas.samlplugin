from zope.interface import Interface

class ISAMLLogoutHandler(Interface):
    """
    handle SAML2  Logout
    """
    
    def slo(request):
        """
        generate a SAML2 single logout request, return url
        """

    def redirect_logout_request(request):
        """
        redirect the request to SAML2 IDP logout endpoint
        """

class ISAMLAttributeProvider(Interface):
    """
    provides access to attributes sent by IDP in AttributeStatement after login
    """

    def attributes(request):
        """
        the attributes
        """

class ISAMLSessionCheck(Interface):
    """
    explicitly perform a SAML session check
    """

    def checksession(request):
        """
        check the session (passive session check)
        """

    def active(request):
        """
        perform an active session check, i.e. redirect to the IDP's login page if there is no SSO session
        """

    def passive(request):
        """
        perform a passive session check
        """

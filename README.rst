Introduction
============

``hl.pas.samlplugin`` provides a SAML2 plugin for Zope's `PluggableAuthService 
<http://pypi.python.org/pypi/Products.PluggableAuthService>`__. It provides 
the IExtractionPlugin, IAuthenticationPlugin, IChallengePlugin, ICredentialsResetPlugin
interfaces.

``hl.pas.samlplugin`` so far has been tested with OpenAM.

Installation
============

1. Add the package to your buildout.
2. Run buildout. ``hl.pas.samlplugin`` will pull in `pysaml2 <http://pypi.python.org/pypi/pysaml2/0.4.2>`__, 
   which in turn needs xmlsec and repoze.who. xmlsec has to be installed manually, please refer to the pysaml2 
   documentation.
3. Restart Zope.
4. Visit your site's Pluggable Auth Service in ZMI and add a SAML2 PAS plugin

Configuration
=============

You will need to provide your IDP with an endpoint configuration for your Zope site containing your sites' 
settings for AssertionConsumerService and SingleLogoutService. This will be an XML file looking like e.g::

    <EntityDescriptor entityID="http://zopehost:8080/spEntityID" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
        <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="false"
                         protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                 Location="http://zopehost:8080/site/logout"
                                 ResponseLocation="https://zopehost:8080/site/logout"/>
            <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
            <AssertionConsumerService isDefault="true" index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="http://zopehost:8080/site"/> 
        </SPSSODescriptor>
        <RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                        xmlns:query="urn:oasis:names:tc:SAML:metadata:ext:query"
                        xsi:type="query:AttributeQueryDescriptorType"
                        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        </RoleDescriptor>
    </EntityDescriptor>

At the moment the bindings specified in the above example (i.e. HTTP-Redirect for the SingleLogoutService and HTTP-POST 
for the AssertionConsumerService) are the only ones that are supported. For the authentication request, HTTP-Redirect is used.

Please refer to available SAML2 documentation for further information.

On the SAML2 PAS plugins' properties tab, you will need to specify some more properties to make things work:

- the absolute path to the IDP config file. This XML file should be provided by your IDP
- the service endpoint URL, i.e. http://zopehost:8080/site in the example above
- the service endpoint entity id as given to the IDP
- the absolute path to the xmlsec executable (s. pysaml2 documentation)
- the attribute provided by the IDP that should be used as the users login attribute (i.e. the user id used by Zope)
- additional user properties given by the IDP that should be stored in the users session

Please have a look in the ``browser`` and the ``skins/auth`` subdirectories for examples on how to handle login/logout 
for a CMFSite.

It seems important to note that this PAS plugin (and the SAML2 protocol) only provides authentication. It is rather likely 
that you will have to implement your own plugins to provide the IPropertiesPlugin and the IUserEnumerationPlugin interfaces, 
at least if you have to deal with user generated content or want to use the Zope CMF.

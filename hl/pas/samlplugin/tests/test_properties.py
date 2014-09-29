import unittest
from zope.interface.verify import verifyObject
from Products.PluggableAuthService.interfaces.plugins import IPropertiesPlugin
from .base import SAMLPluginTestsBase
from .mocks import UserMock

class PropertiesTests(SAMLPluginTestsBase):

    def test_properties_of_current_user(self):
        """
        the plugin should read properties of the current user from her session data
        """
        req = self._make_request()
        plugin = self._make_one()
        uid = 'foo'
        session = req.SESSION
        expected = {'firstname':'Thomas', 'lastname':'Schorr', 'salutation':'Herr'}
        session[plugin.session_user_properties] = expected
        session.set(plugin.session_login_key, uid)
        got = plugin.getPropertiesForUser(UserMock(uid), req)
        self.failUnless(expected==got, 'Expected %s, got %s instead' % (expected, got))
        # request might be None, then the plugin uses acquisition
        plugin.REQUEST = req
        got = plugin.getPropertiesForUser(UserMock(uid))
        self.failUnless(expected==got, 'Expected %s, got %s instead' % (expected, got))

    def test_properties_of_other_user(self):
        """
        for users other than the current user, the plugin should not return properties data
        """
        req = self._make_request()
        plugin = self._make_one()
        uid = 'foo'
        session = req.SESSION
        userdata = {'firstname':'Thomas', 'lastname':'Schorr', 'salutation':'Herr'}
        expected = {}
        session[plugin.session_user_properties] = userdata
        session.set(plugin.session_login_key, uid)
        got = plugin.getPropertiesForUser(UserMock('bar'), req)
        self.failUnless(expected==got, 'Expected %s, got %s instead' % (expected, got))

    def test_properties_no_saml_sessiondata(self):
        """
        if the SAML2 plugin is not used for credential extraction and authentication, then
        most likely there will be no properties. We expect an empty dict in this case.
        """
        req = self._make_request()
        plugin = self._make_one()
        uid = 'foo'
        expected = {}
        got = plugin.getPropertiesForUser(UserMock(uid), req)
        self.failUnless(expected==got, 'Expected %s, got %s instead' % (expected, got))

    def test_interfaces(self):
        """
        interface implementations
        """
        plugin = self._make_one()
        self.assert_(verifyObject(IPropertiesPlugin, plugin))

def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(PropertiesTests),
        ))

if __name__ == '__main__':
    from Products.GenericSetup.testing import run
    run(test_suite())


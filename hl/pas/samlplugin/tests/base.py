import sys
import os
import unittest
from ZPublisher.HTTPRequest import HTTPRequest
from ZPublisher.HTTPResponse import HTTPResponse
from .mocks import SessionMock


class SAMLPluginTestsBase(unittest.TestCase):

    path = os.path.dirname(__file__)

    def _get_target_class(self):
        from hl.pas.samlplugin.plugin import SAML2Plugin
        return SAML2Plugin

    def _make_one(self):
        o = self._get_target_class()('saml2')
        o.saml2_user_properties = ('FirstName', 'LastName', 'Email')
        o.saml2_idp_configfile = os.path.join(self.path, 'data', 'idp.xml')
        o.saml2_sp_url = 'http://nohost/'
        o.saml2_sp_entityid = 'http://nohost/'
        o.saml2_xmlsec = '/usr/bin/xmlsec1'
        o.saml2_login_attribute = 'Email'
        return o

    def _make_request(self):
        environ = {}
        environ['SERVER_NAME'] = 'foo'
        environ['SERVER_PORT'] = '80'
        environ['REQUEST_METHOD'] = 'GET'
        resp = HTTPResponse(stdout=sys.stdout)
        req = HTTPRequest(stdin=file, environ=environ, response=resp)
        session = SessionMock()
        req.other['SESSION'] = session
        req['ACTUAL_URL'] = 'http://nohost/'
        return req


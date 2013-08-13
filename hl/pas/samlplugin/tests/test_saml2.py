# -*- coding: utf-8 -*-
import sys
import os
import unittest
import sgmllib
import base64
import urllib
from datetime import datetime, timedelta
from cStringIO import StringIO
from UserDict import UserDict
from ZPublisher.HTTPRequest import HTTPRequest
from ZPublisher.HTTPResponse import HTTPResponse
from zope.interface.verify import verifyObject
from saml2.saml import Issuer, Assertion
from saml2.saml import Subject, NameID, SubjectConfirmation, SubjectConfirmationData
from saml2.saml import Conditions, AudienceRestriction, Audience, OneTimeUse
from saml2.saml import AuthnStatement, AuthnContext, AuthnContextClassRef
from saml2.saml import attribute_statement_from_string
from saml2.saml import NAMEID_FORMAT_TRANSIENT, SCM_BEARER
from saml2.saml import NAMEID_FORMAT_ENTITY
from saml2.samlp import Response, Status, StatusCode
from saml2.samlp import STATUS_SUCCESS
from saml2.samlp import authn_request_from_string, logout_request_from_string, logout_response_from_string
from saml2.sigver import pre_signature_part, SecurityContext, CryptoBackendXmlSec1
from saml2.s_utils import decode_base64_and_inflate, deflate_and_base64_encode
from hl.pas.samlplugin.interfaces import ISAMLLogoutHandler, ISAMLAttributeProvider, ISAMLSessionCheck


path = os.path.dirname(__file__)


class SessionMock(UserDict):

    id = 'dummy'

    def set(self, k, v):
        self[k] = v

    def __getitem__(self, k, default=None):
        if self.has_key(k):
            return UserDict.__getitem__(self, k)
        return default

    delete = UserDict.__delitem__


class URLOpenResponseMock(object):

    shared_state = {}

    def __init__(self, status, request):
        self.__dict__ = self.shared_state
        self.code = status
        self.request = request 


class FormParser(sgmllib.SGMLParser):

    def __init__(self, verbose=0):
        sgmllib.SGMLParser.__init__(self, verbose)
        self.inputs = {}

    def parse(self, s):
        self.feed(s)
        self.close()

    def start_input(self, attributes):
        name = value = None
        for attr_key, attr_value in attributes:
            if attr_key == 'name':
                name = attr_value
            if attr_key == 'value':
                value = attr_value
        if name is not None and value is not None:
            self.inputs[name] = value


class SAML2PluginTests(unittest.TestCase):

    session_index = 's24d8e3c95e92e861f791016d32f92a8e588686101'
    attribute_xml = """<ns1:AttributeStatement xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"><ns1:Attribute Name="SSOToken"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">AQIC5wM2LY4SfcwB-hRxD21HHhBm_8RO3TkGHKhcWmmGaUc.*AAJTSQACMDE.*</ns1:AttributeValue></ns1:Attribute><ns1:Attribute Name="HMGUSERID"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">829c6d29-5a0f-4d91-9617-a686614dd6fd</ns1:AttributeValue></ns1:Attribute><ns1:Attribute Name="huid"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">1701765</ns1:AttributeValue></ns1:Attribute><ns1:Attribute Name="Salutation"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">Herr</ns1:AttributeValue></ns1:Attribute><ns1:Attribute Name="Title"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance" /></ns1:Attribute><ns1:Attribute Name="FirstName"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">Thomas</ns1:AttributeValue></ns1:Attribute><ns1:Attribute Name="LastName"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">Schorr</ns1:AttributeValue></ns1:Attribute><ns1:Attribute Name="Email"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">thomas.schorr@haufe-lexware.com</ns1:AttributeValue></ns1:Attribute></ns1:AttributeStatement>"""


    def setUp(self):
        self._stored_urlopen = urllib.urlopen
        urllib.urlopen = lambda url: URLOpenResponseMock(200, url)


    def tearDown(self):
        urllib.urlopen = self._stored_urlopen

    def _get_target_class(self):
        from hl.pas.samlplugin.plugin import SAML2Plugin
        return SAML2Plugin


    def _make_one(self):
        o = self._get_target_class()('atlantikSSIPlugin')
        o.saml2_user_properties = ('FirstName', 'LastName', 'huid')
        o.saml2_idp_configfile = os.path.join(path, 'data', 'idp.xml')
        o.saml2_sp_url = 'http://nohost/'
        o.saml2_sp_entityid = 'http://nohost/'
        o.saml2_xmlsec = '/usr/bin/xmlsec1'
        o.saml2_login_attribute = 'huid'
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


    def _parse_authn_request(self, enc_request):
        """
        enc_request is an encrypted and base64 encoded request
        """
        xmlstr = decode_base64_and_inflate(urllib.unquote(enc_request))
        return authn_request_from_string(xmlstr)

    def _parse_logout_request(self, enc_request):
        xmlstr = decode_base64_and_inflate(urllib.unquote(enc_request))
        return logout_request_from_string(xmlstr)

    def _parse_logout_response(self, enc_response):
        xmlstr = decode_base64_and_inflate(urllib.unquote(enc_response))
        return logout_response_from_string(xmlstr)

    def _create_idp_logout_request(self):
        """
        enc_resp is an encrypted and base64 encoded logout response
        """
        logout_xml = '<samlp:LogoutRequest  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="s26bce413ad43ae7ff430a065122b7b16f31e17802" Version="2.0" IssueInstant="2012-05-08T12:46:11Z" Destination="http://zopedev2.haufe-ep.de:23680/kundenbereich/logout" NotOnOrAfter="2012-05-08T12:56:11Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://nohost/auth</saml:Issuer><saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="http://nohost/auth" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">1kFn6vXCTJ7Uo5v572Z1IsaLK8yQ</saml:NameID><samlp:SessionIndex xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">s26997d5ef9cbf708cc46b732624d90bba15cfb101</samlp:SessionIndex></samlp:LogoutRequest>'
        return deflate_and_base64_encode(logout_xml)
        
    def _create_idp_response(self, authn_request_id='2aaaeb7692471eb4ba00d5546877a7fd'):
        issue_instant = datetime.utcnow().isoformat() + 'Z'
        not_before = (datetime.utcnow() - timedelta(minutes=5)).isoformat() + 'Z'
        not_on_or_after = (datetime.utcnow() + timedelta(minutes=5)).isoformat() + 'Z'
        issuer = Issuer(format=NAMEID_FORMAT_ENTITY, text='http://nohost/auth')
        signature = pre_signature_part('s2998eb2e03b5006acb0a931d0fb558b0e4ec360c7')
        status = Status(status_code=StatusCode(value=STATUS_SUCCESS))
        subject_confirmation_data = SubjectConfirmationData(not_on_or_after=not_on_or_after,
                                                            in_response_to=authn_request_id,
                                                            recipient='http://nohost/')
        subject_confirmation = SubjectConfirmation(method=SCM_BEARER,
                                                   subject_confirmation_data=subject_confirmation_data)
        subject = Subject(name_id=NameID(text='AABVSVesMLYDiHtowyX4MDu6UopU', format=NAMEID_FORMAT_TRANSIENT),
                          subject_confirmation=subject_confirmation)
        conditions = Conditions(not_before=not_before,
                                not_on_or_after=not_on_or_after,
                                audience_restriction=AudienceRestriction(Audience('http://nohost/')),
                                one_time_use=OneTimeUse())
        authn_context = AuthnContext(authn_context_decl_ref=AuthnContextClassRef('urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'))
        authn_statement = AuthnStatement(authn_instant=issue_instant,
                                         authn_context=authn_context,
                                         session_index=self.session_index)
        attribute_statement = attribute_statement_from_string(self.attribute_xml)
        assertion = Assertion(id='s2bb879ef893d1b27fb90903e7c7e2779a3e7502c1',
                              version='2.0',
                              issue_instant=issue_instant,
                              issuer=issuer,
                              subject=subject,
                              conditions=conditions,
                              authn_statement=authn_statement,
                              attribute_statement=attribute_statement,
                             )

        response = Response(id='s2998eb2e03b5006acb0a931d0fb558b0e4ec360c7',
                            in_response_to=authn_request_id,
                            version='2.0',
                            issue_instant=issue_instant,
                            destination='http://nohost/',
                            issuer=issuer,
                            signature=signature,
                            status=status,
                            assertion=assertion,
                           )

        return response

    def sign_response(self, response):
        response = '%s' % response
        # Sign assertion in the response
        xmlsec = CryptoBackendXmlSec1(os.environ.get('SAML2_XMLSEC', '/usr/bin/xmlsec1'))
        seccont = SecurityContext(xmlsec, key_file=os.path.join(path, 'data', 'test.key'))
        signed_response = seccont.sign_statement(response, 'urn:oasis:names:tc:SAML:2.0:protocol:Response')
        return signed_response

    
    def test_authenticate(self):
        creds = {'ssiauth':True, 'login':'1701765'}
        plugin = self._make_one()
        expected = ('1701765', '1701765')
        got = plugin.authenticateCredentials(creds)
        self.failUnless(expected == got, 'expected %s, got %s' % (expected, got))
        creds['ssiauth'] = False
        got = plugin.authenticateCredentials(creds)
        self.failUnless(got == None, 'authenticated in spite of invalid credentials, got %s' % got)

    def test_extract_credentials(self):
        plugin = self._make_one()
        req = self._make_request()
        resp = req.response
        plugin.extractCredentials(req)
        self.assertEquals(resp.status, 302, 'Redirect not set, status is: %s' % resp.status)
        get = resp.getHeader('location')
        urlvars = {}
        urlvars.update([tuple(get.split('?')[1].split('='))])
        saml_request = urlvars.get('SAMLRequest', '')
        request = self._parse_authn_request(saml_request)
        self.assertEquals(request.destination, 'http://nohost/auth/SSORedirect/metaAlias/idp')
        expected = 'http://nohost/'
        self.assertEquals(request.assertion_consumer_service_url, expected, 'unexpected assertion consumer service url, expected %s, got %s.' % (expected, request.assertion_consumer_service_url))

    def test_response_extraction(self):
        plugin = self._make_one()
        req = self._make_request()
        # Create a SAML2 response
        response = '%s' % self._create_idp_response('id-8201d3b76aa96ecc4317e55ec4f968ee')
        signed_response = self.sign_response(response)
        encoded_response = base64.b64encode(signed_response)
        req.form['SAMLResponse'] = encoded_response
        req.environ['REQUEST_METHOD'] = 'POST'
        req.stdin = StringIO(urllib.urlencode({'SAMLResponse' : encoded_response}))
        session = req.SESSION
        session.set('_saml2_storedurl', 'http://nohost/stored_url')
        session.set('_saml2_sessid', {'2aaaeb7692471eb4ba00d5546877a7fd':''})
        creds = plugin.extractCredentials(req)
        self.assertEquals(creds['login'], '1701765')
        got = session.get('_saml2_session_index', '')
        self.assertEquals(got, self.session_index, 'Expected session index %s, got %s' % (self.session_index, got))
    
    def test_active(self):
        plugin = self._make_one()
        req = self._make_request()
        resp = req.response
        referer = 'http://nohost/referer'
        req.HTTP_REFERER = referer
        session = req.SESSION
        session.set('_saml2_ssi_auth', True)
        result = plugin.active(req)
        self.failUnless(result == True, 'challenge failed')
        got = session.get('_saml2_storedurl', '')
        self.failUnless(got == referer, 'expected stored url %s in session, got %s' % (referer, got))
        # challenge should set the stored saml session id
        got = session.get('_saml2_sessid', '')
        self.failUnless(got != '', 'Expected saml session id to be set in local session')
        self.failUnless(session['_saml2_ssi_auth'] == False, 'challenge should reset the authentication flag in the session.')
        # the rest should be the same as credentials extraction
        self.assertEquals(resp.status, 302, 'Redirect not set, status is: %s' % resp.status)
        get = resp.getHeader('location')
        urlvars = {}
        urlvars.update([tuple(get.split('?')[1].split('='))])
        saml_request = urlvars.get('SAMLRequest', '')
        request = self._parse_authn_request(saml_request)
        self.assertEquals(request.destination, 'http://nohost/auth/SSORedirect/metaAlias/idp')
        expected = 'http://nohost/'
        self.assertEquals(request.assertion_consumer_service_url, expected, 'unexpected assertion consumer service url, expected %s, got %s.' % (expected, request.assertion_consumer_service_url))

    def test_challenge(self):
        request = self._make_request()
        response = request.response
        test_url = request['ACTUAL_URL']
        helper = self._make_one()
        helper.challenge(request, response)
        self.assertEqual(response.status, 302)
        self.assertEqual(len(response.headers), 3)
        self.failUnless(response.headers['location'].endswith(urllib.quote(test_url)))
        self.assertEqual(response.headers['cache-control'], 'no-cache')
        self.assertEqual(response.headers['expires'], 'Sat, 01 Jan 2000 00:00:00 GMT')

    def test_reset_credentials(self):
        req = self._make_request()
        plugin = self._make_one()
        resp = req.RESPONSE
        session = req.SESSION
        session.set('_saml2_uid', 'testtest')
        session.set('_saml2_ssi_auth', True)
        session.set('_saml2_session_user_properties', {'foo':'bar'})
        req.URL1 = 'http://nohost/url1'
        plugin.resetCredentials(req, resp)
        self.failUnless(not session.get('_saml2_ssi_auth', True), 'not logged out')

    def test_slo(self):
        req = self._make_request()
        plugin = self._make_one()
        session = req.SESSION
        session.set('_saml2_uid', 'testtest')
        session.set('_saml2_ssi_auth', True)
        session.set('_saml2_session_user_properties', {'foo':'bar'})
        req.URL1 = 'http://nohost/url1'
        get = plugin.slo(req)
        urlvars = {}
        urlvars.update(tuple([kv.split('=') for kv in get.split('?')[1].split('&')]))
        saml_request = urlvars.get('SAMLRequest', '')
        request = self._parse_logout_request(saml_request)
        self.failUnless(request.issuer.text == 'http://nohost/', 'wrong issuer, got: %s' % request.issuer.text)
        self.failUnless(request.destination == 'http://nohost/auth/IDPSloRedirect/metaAlias/idp', 'wrong destination: %s' % request.destination)
        self.failUnless(request.name_id.text == 'testtest', 'wrong NameID: %s' % request.name_id.text)
        self.failUnless(not session.get('_saml2_ssi_auth', True), 'not logged out')

    def test_redirect_logout_request(self):
        req = self._make_request()
        plugin = self._make_one()
        session = req.SESSION
        resp = req.RESPONSE
        session.set('_saml2_ssi_auth', True)
        session.set('_saml2_session_index', 's26997d5ef9cbf708cc46b732624d90bba15cfb101')
        req.form['SAMLRequest'] = self._create_idp_logout_request()
        plugin.redirect_logout_request(req)
        self.assertEquals(resp.status, 302, 'Redirect not set, status is: %s' % resp.status)
        get = resp.getHeader('location')
        urlvars = {}
        urlvars.update([tuple(get.split('?')[1].split('='))])
        saml_response = urlvars.get('SAMLResponse')
        response = self._parse_logout_response(saml_response)
        self.failUnless(response.status.status_code.value == 'urn:oasis:names:tc:SAML:2.0:status:Success', 'unexpected logout status: %s' % response.status.status_code.value)
        session.set('_saml2_session_index', 'invalidsessionidx')
        plugin.redirect_logout_request(req)
        self.assertEquals(resp.status, 302, 'Redirect not set, status is: %s' % resp.status)
        get = resp.getHeader('location')
        urlvars = {}
        urlvars.update([tuple(get.split('?')[1].split('='))])
        saml_response = urlvars.get('SAMLResponse')
        response = self._parse_logout_response(saml_response)
        self.failUnless(response.status.status_code.value == 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied', 'unexpected logout status: %s' % response.status.status_code.value)

    def test_checksession_passive_with_query(self):
        """
        should be the same as extractCredentials
        """
        plugin = self._make_one()
        req = self._make_request()
        req['ACTUAL_URL'] = req.SERVER_URL = 'http://nohost/somepath'
        qs = 'x=1&y:int=2'
        req.environ['QUERY_STRING'] = qs
        req.form.update({'x':'1', 'y':2})
        plugin.checksession(req)
        expected = 'http://nohost/somepath'
        session_storedurl_key = plugin.session_storedurl_key
        address, querystring = req.SESSION.get(session_storedurl_key).split('?')
        self.assertEquals(address, expected, 'unexpected stored url in session, expected %s, got %s.' % (expected, address))
        expected = dict([ item.split('=') for item in qs.split('&')])
        paramsOut = dict([ item.split('=') for item in querystring.split('&')])
        self.assertEquals(paramsOut, expected, 'unexpected querystring in stored url, expected: %s, got: %s' %(expected, paramsOut))
    
    def test_checksession_passive(self):
        """
        should be the same as extractCredentials
        """
        plugin = self._make_one()
        req = self._make_request()
        resp = req.response
        plugin.checksession(req)
        self.assertEquals(resp.status, 302, 'Redirect not set, status is: %s' % resp.status)
        get = resp.getHeader('location')
        urlvars = {}
        urlvars.update([tuple(get.split('?')[1].split('='))])
        saml_request = urlvars.get('SAMLRequest', '')
        request = self._parse_authn_request(saml_request)
        self.assertEquals(request.destination, 'http://nohost/auth/SSORedirect/metaAlias/idp')
        expected = 'http://nohost/'
        self.assertEquals(request.assertion_consumer_service_url, expected, 'unexpected assertion consumer service url, expected %s, got %s.' % (expected, request.assertion_consumer_service_url))


        

    def test_interfaces(self):
        """
        interface implementations
        """
        plugin = self._make_one()
        self.assert_(verifyObject(ISAMLLogoutHandler, plugin))
        self.assert_(verifyObject(ISAMLAttributeProvider, plugin))
        self.assert_(verifyObject(ISAMLSessionCheck, plugin))
    
def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(SAML2PluginTests),
        ))

if __name__ == '__main__':
    from Products.GenericSetup.testing import run
    run(test_suite())


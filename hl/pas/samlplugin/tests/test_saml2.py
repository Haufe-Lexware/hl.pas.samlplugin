# -*- coding: utf-8 -*-
import sys
import os
import unittest
import sgmllib
import base64
import urllib
import requests
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
from saml2.time_util import instant
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


class ResponseMock(object):

    shared_state = {}
    text = ''

    def __init__(self, status, request, method=None, **kwargs):
        self.__dict__ = self.shared_state
        self.code = self.status_code = status
        self.request = request 
        self.method = method
        self.kwargs = kwargs


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
    attribute_xml = \
        """<ns1:AttributeStatement xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"><ns1:Attribute Name="SSOToken"><ns1:AttributeValue ns2:type="xs:string" """\
        """xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">AQIC5wM2LY4SfcwB-hRxD21HHhBm_8RO3TkGHKhcWmmGaUc.*AAJTSQACMDE.*</ns1:AttributeValue></ns1:Attribute>"""\
        """<ns1:Attribute Name="Salutation"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">Herr</ns1:AttributeValue></ns1:Attribute>"""\
        """<ns1:Attribute Name="Title"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance" /></ns1:Attribute>"""\
        """<ns1:Attribute Name="FirstName"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">Thomas</ns1:AttributeValue></ns1:Attribute>"""\
        """<ns1:Attribute Name="LastName"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">Schorr</ns1:AttributeValue></ns1:Attribute>"""\
        """<ns1:Attribute Name="Email"><ns1:AttributeValue ns2:type="xs:string" xmlns:ns2="http://www.w3.org/2001/XMLSchema-instance">thomas.schorr@haufe-lexware.com</ns1:AttributeValue></ns1:Attribute></ns1:AttributeStatement>"""
    soap_artifact_response = \
        """<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><soap-env:Body>"""\
        """<samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="s2f3c21d52024a3866e44c5f2e2e00e0f28561830a" """\
        """InResponseTo="id-912c05fb95f9763132f259422bb26113" Version="2.0" IssueInstant="%s" Destination="https://nohost">"""\
        """<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://nohost/auth</saml:Issuer><samlp:Status xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">"""\
        """<samlp:StatusCode  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>"""\
        """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="s284dfd45f100f4a7b1ed1cb25a28ab42e63fc3d0a" InResponseTo="id-80c25be5605f68e2aa4e72660d736d7b" Version="2.0" """\
        """IssueInstant="2014-04-16T12:04:42Z" Destination="https://nohost"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">"""\
        """https://nohost/auth</saml:Issuer><samlp:Status xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:StatusCode  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" """\
        """Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>"""\
        """<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="s208ceb5d27c072d35ca6b2c29211788cb80beea8e" IssueInstant="2014-04-16T12:04:42Z">"""\
        """<saml:Issuer>https://nohost/auth</saml:Issuer><saml:Subject><saml:NameID NameQualifier="https://nohost/auth" """\
        """Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">3TJes2TmJbwUrxplHOKeFcjty1l7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">"""\
        """<saml:SubjectConfirmationData NotOnOrAfter="2014-04-16T12:14:42Z" InResponseTo="id-80c25be5605f68e2aa4e72660d736d7b" Recipient="https://nohost" >"""\
        """</saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-04-16T11:54:42Z" NotOnOrAfter="2014-04-16T12:14:42Z">"""\
        """<saml:AudienceRestriction><saml:Audience>https://nohost/</saml:Audience></saml:AudienceRestriction></saml:Conditions>"""\
        """<saml:AuthnStatement AuthnInstant="2014-04-15T14:52:34Z" SessionIndex="s2d7759b46741a35f5a93a4deb620ed1468e6dc901"><saml:AuthnContext><saml:AuthnContextClassRef>"""\
        """urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>"""\
        """<saml:Attribute Name="SSOToken"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">"""\
        """AQIC5wM2LY4Sfczx22Y4ngUTZ7fqv3OG9-3jNcSf2NNqpsE.*AAJTSQACMDIAAlMxAAIwMQ..*</saml:AttributeValue></saml:Attribute><saml:Attribute Name="AuthLevel">"""\
        """<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">15</saml:AttributeValue></saml:Attribute>"""\
        """<saml:Attribute Name="Salutation"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">"""\
        """Herr</saml:AttributeValue></saml:Attribute><saml:Attribute Name="FirstName"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">"""\
        """Thomas</saml:AttributeValue></saml:Attribute><saml:Attribute Name="LastName"><saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" """\
        """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Schorr</saml:AttributeValue></saml:Attribute><saml:Attribute Name="Email">"""\
        """<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">thomas.schorr@haufe-lexware.com"""\
        """</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response></samlp:ArtifactResponse></soap-env:Body></soap-env:Envelope>""" % instant()


    def setUp(self):
        self._stored_urlopen = urllib.urlopen
        self._stored_request = requests.request
        urllib.urlopen = lambda url: ResponseMock(200, url)
        requests.request = lambda method, url, **kwargs: ResponseMock(200, url, method, **kwargs)

    def tearDown(self):
        urllib.urlopen = self._stored_urlopen
        requests.request = self._stored_request

    def _get_target_class(self):
        from hl.pas.samlplugin.plugin import SAML2Plugin
        return SAML2Plugin


    def _make_one(self):
        o = self._get_target_class()('saml2')
        o.saml2_user_properties = ('FirstName', 'LastName', 'Email')
        o.saml2_idp_configfile = os.path.join(path, 'data', 'idp.xml')
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
        logout_xml = '<samlp:LogoutRequest  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="s26bce413ad43ae7ff430a065122b7b16f31e17802" Version="2.0" IssueInstant="2012-05-08T12:46:11Z" Destination="http://nohost/logout" NotOnOrAfter="2012-05-08T12:56:11Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://nohost/auth</saml:Issuer><saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="http://nohost/auth" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">1kFn6vXCTJ7Uo5v572Z1IsaLK8yQ</saml:NameID><samlp:SessionIndex xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">s26997d5ef9cbf708cc46b732624d90bba15cfb101</samlp:SessionIndex></samlp:LogoutRequest>'
        return deflate_and_base64_encode(logout_xml)
        
    def _create_idp_response(self, authn_request_id='2aaaeb7692471eb4ba00d5546877a7fd', cls=Response):
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

        return cls(id='s2998eb2e03b5006acb0a931d0fb558b0e4ec360c7',
                   in_response_to=authn_request_id,
                   version='2.0',
                   issue_instant=issue_instant,
                   destination='http://nohost/',
                   issuer=issuer,
                   signature=signature,
                   status=status,
                   assertion=assertion)

    def sign_response(self, response):
        response = '%s' % response
        # Sign assertion in the response
        xmlsec = CryptoBackendXmlSec1(os.environ.get('SAML2_XMLSEC', '/usr/bin/xmlsec1'))
        seccont = SecurityContext(xmlsec, key_file=os.path.join(path, 'data', 'test.key'))
        signed_response = seccont.sign_statement(response, 'urn:oasis:names:tc:SAML:2.0:protocol:Response')
        return signed_response

    
    def test_authenticate(self):
        creds = {'ssiauth':True, 'login':'thomas.schorr@haufe-lexware.com'}
        plugin = self._make_one()
        expected = ('thomas.schorr@haufe-lexware.com', 'thomas.schorr@haufe-lexware.com')
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
        self.assertEquals(creds['login'], 'thomas.schorr@haufe-lexware.com')
        got = session.get('_saml2_session_index', '')
        self.assertEquals(got, self.session_index, 'Expected session index %s, got %s' % (self.session_index, got))

    def test_passive_artifact_response(self):
        plugin = self._make_one()
        req = self._make_request()
        ResponseMock.text = self.soap_artifact_response
        req.form['SAMLart'] = 'AAQAAJua9tAo9a1t0STYSpdn907OIx0lhLC5QgJKy9SOtEaeXyj7sON2MDE='
        req.environ['REQUEST_METHOD'] = 'GET'
        session = req.SESSION
        session.set('_saml2_storedurl', 'http://nohost/stored_url')
        creds = plugin.passive(req)
        self.failUnless(type(creds) == dict, 'unexpected credentials: %s' % creds)
        self.failUnless(creds['login'] == 'thomas.schorr@haufe-lexware.com', 'unexpected credentials: %s' % creds)
        self.failUnless(creds['ssiauth'], 'unexpected credentials: %s' % creds)
    
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


    def test_authn_context(self): 
        plugin = self._make_one()
        for method in (plugin.active, plugin.passive):
            for ac in plugin.possible_authn_context_types:
                req = self._make_request()
                resp = req.response
                plugin.saml2_authn_context_class = ac
                method(req)
                get = resp.getHeader('location')
                urlvars = {}
                urlvars.update([tuple(get.split('?')[1].split('='))])
                saml_request = urlvars.get('SAMLRequest', '')
                request = self._parse_authn_request(saml_request)
                if ac == 'do not specify':
                    self.failUnless(request.requested_authn_context is None, 'bogus request: %s' % request.to_string())
                    continue
                self.failUnless(len(request.requested_authn_context.authn_context_class_ref) == 1, 'bogus request: %s' % request.requested_authn_context.to_string())
                got = request.requested_authn_context.authn_context_class_ref[0].text
                self.failUnless(got == ac, 'unexpected authn context class - got %s, expected %s.' % (got, ac))

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


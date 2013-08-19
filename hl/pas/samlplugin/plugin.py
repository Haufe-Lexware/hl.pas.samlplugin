import os
import cgi
import logging
from urllib import quote
from cStringIO import StringIO
from AccessControl.SecurityInfo import ClassSecurityInfo
from Persistence import PersistentMapping
from App.class_init import default__class_init__ as InitializeClass
from AccessControl.Permissions import view
from ZTUtils import make_query
from zope.component import adapter
from zope.site.hooks import getSite
from zope.app.container.interfaces import IObjectAddedEvent
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins import \
     IExtractionPlugin, IAuthenticationPlugin, IChallengePlugin, ICredentialsResetPlugin
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from saml2.config import SPConfig
from saml2 import saml, samlp
from saml2.sigver import signed_instance_factory
from saml2.pack import http_redirect_message
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.saml import NAME_FORMAT_URI
from saml2.mdstore import destinations
from client import Saml2Client
from interfaces import ISAMLLogoutHandler, ISAMLAttributeProvider, ISAMLSessionCheck

logger = logging.getLogger('hl.pas.samlplugin')


manage_addSAML2PluginForm = PageTemplateFile(
    'www/addSAML2Plugin', globals(), __name__='manage_addSAML2PluginForm' )


def addSAML2Plugin(dispatcher, id, title=None, REQUEST=None):
    """
    Add a SAML2 PAS plugin to a Pluggable Auth Service.
    """
    sp = SAML2Plugin(id, title)
    dispatcher._setObject(sp.getId(), sp)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect('%s/manage_workspace'
                                     '?manage_tabs_message='
                                     'SAML2Plugin+added.'
                                    % dispatcher.absolute_url())


class SAML2Plugin(BasePlugin):
    """
    SAML2 Authentication.
    """

    security = ClassSecurityInfo()
    meta_type = 'SAML2 PAS plugin'

    session_auth_key = '_saml2_ssi_auth'
    session_login_key = '_saml2_login'
    session_samluid_key = '_saml2_uid'
    session_samlsessionindex_key = '_saml2_session_index'
    session_storedurl_key = '_saml2_storedurl'
    session_lock_key = '_saml2_lock'
    session_sessid = '_saml2_sessid'
    session_user_properties = '_saml2_session_user_properties'
    _v_config = None

    # ZMI properties
    saml2_idp_configfile = '%s/idp.xml' % os.getcwd()
    saml2_sp_url = '<portal_url>'
    saml2_sp_entityid = '<entity_id>'
    saml2_xmlsec = '/usr/bin/xmlsec1'
    saml2_login_attribute = 'email'
    saml2_user_properties = ('firstname', 'lastname', 'email')
    _properties = BasePlugin._properties + (
        {'id':'saml2_idp_configfile', 'label':'path to IDP config file', 'type':'string', 'mode':'rw'},
        {'id':'saml2_sp_url', 'label':'SP URL', 'type':'string', 'mode':'rw'},
        {'id':'saml2_sp_entityid', 'label':'SP entity id', 'type':'string', 'mode':'rw'},
        {'id':'saml2_xmlsec', 'label':'path to xmlsec executable', 'type':'string', 'mode':'rw'},
        {'id':'saml2_login_attribute', 'label':'SAML2 attribute used as login', 'type':'string', 'mode':'rw'},
        {'id':'saml2_user_properties', 'label':'SAML2 user properties given by sso server', 'type':'lines', 'mode':'rw'},
        )

    @staticmethod
    def _saml2_config_template():
        return {
                "entityid" : None,
                "service": {
                    "sp":{
                    "name" : None,
                    "url" : None,
                    "endpoints":{
                        "assertion_consumer_service": None,
                        "single_logout_service":None,
                        },
                    "required_attributes": [],
                    "optional_attributes": [],
                    "privacy_notice": "",
                    "allow_unsolicited":True,
                    }
                },
                "metadata" : {
                    "local" : None,
                    },
                "debug" : 1,
                "key_file" : "",
                "cert_file" : "",
                "accepted_time_diff":0,
                "xmlsec_binary" : None,
                "name_form": NAME_FORMAT_URI
                }

    @classmethod
    def attributes(cls, request=None):
        """
        ISAMLAttributeProvider interface
        """
        if request and request.SESSION.get(cls.session_auth_key):
            return request.SESSION.get(cls.session_user_properties, {})
        return {}
      
    def __init__(self, id, title=None):
        self._setId(id)
        self.title = title

    def _saml2_config(self):
        if self._v_config is None:
            sp_config = self._saml2_config_template()
            sp_config['metadata']['local'] = [self.saml2_idp_configfile]
            sp_config['entityid'] = self.saml2_sp_entityid
            sp_config['service']['sp']['name'] = self.saml2_sp_entityid
            sp_config['service']['sp']['url'] = self.saml2_sp_url
            sp_config['service']['sp']['endpoints']['assertion_consumer_service'] = [self.saml2_sp_url]
            sp_config['service']['sp']['endpoints']['single_logout_service'] = ['%s/logout' % self.saml2_sp_url, BINDING_HTTP_REDIRECT]
            sp_config['service']['sp']['url'] = self.saml2_sp_url
            sp_config['xmlsec_binary'] = self.saml2_xmlsec
            config = SPConfig()
            conf=sp_config.copy()
            config.load(conf)
            self._v_config = config
        return self._v_config

    def _setPropValue(self, id, value):
        """
        override from PropertyManager to invalidate config cache
        """
        super(SAML2Plugin, self)._setPropValue(id, value)
        self._v_config = None

    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):
        """
        This method performs the PAS credential extraction.
        """
        return self.passive(request)

    security.declareProtected(view, 'passive')
    def passive(self, request):
        session = request.SESSION
        if session.get(self.session_auth_key, False):
            session.set(self.session_lock_key, False)
            return {'login': session[self.session_login_key], 'ssiauth':True}
        creds={}
        config = self._saml2_config()
        entityid = config.metadata.keys()[0]
        sp_url = self.saml2_sp_url
        actual_url = request.get("ACTUAL_URL", '')
        if not actual_url.startswith(sp_url):
            # the request was made from within a context we cannot handle
            return None
        actual_url_with_query = '%s?%s' % (actual_url,  make_query(request.form)) if request.get('REQUEST_METHOD') == 'GET' else actual_url
        # Initiate challenge
        if 'SAMLResponse' not in request.form and not session.get(self.session_lock_key, False):
            session.set(self.session_lock_key, True)
            logger.info('ACTUAL_URL: %s' % actual_url)
            scl = Saml2Client(config)
            (sid, result) = scl.authenticate(entityid, binding=BINDING_HTTP_REDIRECT, is_passive='true')
            session.set(self.session_sessid, {sid:''})
            session.set(self.session_storedurl_key, actual_url_with_query)
            headers = dict(result['headers'])
            for k, v in headers.items():
                request.response.setHeader(k, v)
            request.response.redirect(headers['Location'], lock=1)
        # Idp response
        if 'SAMLResponse' in request.form and actual_url.strip('/') == sp_url.strip('/'):
            post_env = request.environ.copy()
            post_env['QUERY_STRING'] = ''

            request.stdin.seek(0)
            post = cgi.FieldStorage(
                fp = StringIO(request.stdin.read()),
                environ = post_env,
                keep_blank_values = True,
            )
            scl = Saml2Client(config)
            storedurl = session.get(self.session_storedurl_key, actual_url_with_query)
            if session.has_key(self.session_storedurl_key):
                session.delete(self.session_storedurl_key)
            request.response.redirect(storedurl)
            session.set(self.session_auth_key, True)
            try:
                session_info = scl.parse_authn_request_response(post['SAMLResponse'].value, BINDING_HTTP_POST, session.get(self.session_sessid, {}))
            except:
                session.set(self.session_auth_key, False)
                # Saml2 auth failed. Do not ask again.
                return None
            ava = session_info.ava.copy()
            login = ava[self.saml2_login_attribute.lower()][0] # whats in 'login' is controlled by the saml2_login_attribute property
            creds['login'] = login
            creds['ssiauth'] = True
            session.set(self.session_user_properties, PersistentMapping(dict([(key, ava[key.lower()][0]) for key in self.saml2_user_properties])))
            session.set(self.session_login_key, login)
            # store relevant information for Single Logout in session
            session.set(self.session_samluid_key, scl.users.subjects()[0].text)
            session.set(self.session_samlsessionindex_key, session_info.assertion.authn_statement[0].session_index)
        return creds

    security.declarePrivate('authenticateCredentials')
    def authenticateCredentials(self, credentials):
        """
        We rely on the SAML2 SSI service to provide only valid credentials
        """
        if credentials.get('ssiauth', False):
            login = credentials.get('login')
            return (login, login)

    security.declarePrivate('challenge')
    def challenge(self, request, response, **kw):
        resp = request['RESPONSE']

        # Redirect if desired.
        url = '{base}/{login}'.format(base=self.absolute_url(), login='login_form')
        came_from = request.get('came_from', None)

        if came_from is None:
            came_from = request.get('ACTUAL_URL', '')
            query = request.get('QUERY_STRING')
            if query:
                if not query.startswith('?'):
                    query = '?' + query
                came_from = came_from + query
        else:
            # If came_from contains a value it means the user
            # must be coming through here a second time
            # Reasons could be typos when providing credentials
            # or a redirect loop (see below)
            req_url = request.get('ACTUAL_URL', '')

            if req_url and req_url == url:
                # Oops... The login_form cannot be reached by the user -
                # it might be protected itself due to misconfiguration -
                # the only sane thing to do is to give up because we are
                # in an endless redirect loop.
                return 0

        if '?' in url:
            sep = '&'
        else:
            sep = '?'
        url = '%s%scame_from=%s' % (url, sep, quote(came_from))
        resp.redirect(url, lock=1)
        resp.setHeader('Expires', 'Sat, 01 Jan 2000 00:00:00 GMT')
        resp.setHeader('Cache-Control', 'no-cache')
        return True

    security.declareProtected(view, 'active')
    def active(self, request):
        """
        we re-extract credentials from the SAML2 service, but with is_pasive=False to initiate a 
        redirect to the login page if no SSI session exists.
        """
        actual_url = request.get("ACTUAL_URL", '')
        sp_url = self.saml2_sp_url
        if not actual_url.startswith(sp_url):
            # the request was made to a URL we cannot handle
            return None
        session = request.SESSION
        session.set(self.session_auth_key, False)
        logger.info('REFERER: %s' % request.HTTP_REFERER)
        session.set(self.session_storedurl_key, request.HTTP_REFERER)
        config = self._saml2_config()
        entityid = config.metadata.keys()[0]
        # Initiate challenge
        scl = Saml2Client(config)
        # if we have an existing SSI session, continue in extractCredentials, otherwise redirect to SAML2 login
        (sid, result) = scl.authenticate(entityid, binding=BINDING_HTTP_REDIRECT)
        session.set(self.session_sessid, {sid:''})
        headers = dict(result['headers'])
        for k, v in headers.items():
            request.response.setHeader(k, v)
        request.response.redirect(headers['Location'], lock=1)
        return True

    security.declareProtected(view, 'checksession')
    def checksession(self, request):
        session = request.SESSION
        session.set(self.session_auth_key, False)
        session.set(self.session_lock_key, False)
        return self.passive(request)

    security.declareProtected(view, 'slo')
    def slo(self, request):
        """
        generate a SAML2 logout request; reset session; return IDP URL
        """
        session = request.SESSION
        session.set(self.session_auth_key, False)
        del session[self.session_user_properties]

        config = self._saml2_config()
        scl = Saml2Client(config)
        samluid = session.get(self.session_samluid_key, '')
        entityid = config.metadata.keys()[0]
        sp_url = self.saml2_sp_url
        actual_url = request.get("ACTUAL_URL", '')
        if not actual_url.startswith(sp_url):
            # the request was made from within a context we cannot handle
            return None
        session.set(self.session_storedurl_key, request.URL1)
        # we cannot simply call global_logout on the client since it doesn't know about our user...
        srvs = scl.metadata.single_logout_service(entityid, BINDING_HTTP_REDIRECT, "idpsso")
        destination = destinations(srvs)[0]
        samlrequest = scl.create_logout_request(destination, entityid, name_id=saml.NameID(text=samluid))
        samlrequest.session_index = samlp.SessionIndex(session.get(self.session_samlsessionindex_key))
        to_sign = []
        samlrequest = signed_instance_factory(samlrequest, scl.sec, to_sign)
        logger.info('SSO logout request: %s' % samlrequest.to_string())
        session_id = samlrequest.id
        rstate = scl._relay_state(session_id)
        msg = http_redirect_message(samlrequest, destination, rstate)
        headers = dict(msg['headers'])
        location = headers['Location']
        logger.info('attempting to post: {loc}'.format(loc=headers['Location']))
        return location

    security.declarePrivate('resetCredentials')
    def resetCredentials(self, request, response):
        """
        ICredentialsResetPlugin interface

        This will reset the local session and send a logout request (the 
        IDP is responsible for invalidating the SSO session).
        This will result in an SSO session check during the next request.
        """
        self.slo(request)

    security.declareProtected(view, 'redirect_logout_request')
    def redirect_logout_request(self, request):
        session = request.SESSION
        session.set(self.session_auth_key, False)
        config = self._saml2_config()
        scl = Saml2Client(config)
        sessidx = session.get(self.session_samlsessionindex_key, '')
        msg = scl.http_redirect_logout_request_check_session_index(request, sessidx, logger)
        headers = dict(msg['headers'])
        return request.response.redirect(headers['Location'], lock=True)
    

classImplements(SAML2Plugin,
                IExtractionPlugin,
                IAuthenticationPlugin,
                IChallengePlugin,
                ICredentialsResetPlugin,
                # SAML interfaces
                ISAMLLogoutHandler,
                ISAMLAttributeProvider,
                ISAMLSessionCheck)

InitializeClass(SAML2Plugin)


@adapter(ISAMLLogoutHandler, IObjectAddedEvent)
def registerSAMLLogoutResponder(plugin, event):
    site = getSite()
    if site is None:
        return
    sm = site.getSiteManager()
    sm.registerUtility(plugin, ISAMLLogoutHandler)

@adapter(ISAMLAttributeProvider, IObjectAddedEvent)
def registerSAMLAttributeProvider(plugin, event):
    site = getSite()
    if site is None:
        return
    sm = site.getSiteManager()
    sm.registerUtility(plugin, ISAMLAttributeProvider)

@adapter(ISAMLSessionCheck, IObjectAddedEvent)
def registerSAMLSessionChecker(plugin, event):
    site = getSite()
    if site is None:
        return
    sm = site.getSiteManager()
    sm.registerUtility(plugin, ISAMLSessionCheck)


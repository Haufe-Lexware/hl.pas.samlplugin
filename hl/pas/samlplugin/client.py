import copy
import logging
import base64
import requests
from binascii import hexlify
from Cookie import SimpleCookie
from saml2.client import Saml2Client as BaseClient
from saml2.s_utils import sid, decode_base64_and_inflate
from saml2 import saml, samlp, class_name, VERSION
from saml2.time_util import instant
from saml2.sigver import pre_signature_part, signed_instance_factory
from saml2.pack import http_redirect_message, make_soap_enveloped_saml_thingy
from saml2.mdstore import destinations
from saml2.entity import ARTIFACT_TYPECODE
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST, BINDING_PAOS

logger = logging.getLogger(__name__)

if requests.__version__ < "2.0.0":
    DICT_HEADERS = False
else:
    DICT_HEADERS = True


class Saml2Client(BaseClient):

    """
    extensions and changes for pysaml2.client.Saml2Client
    """


    def authn_request(self, query_id, destination, service_url, spentityid,
                        my_name="", vorg="", scoping=None, log=None, sign=None,
                        binding=BINDING_HTTP_POST,
                        nameid_format=saml.NAMEID_FORMAT_TRANSIENT, **kwargs):
        """ Creates an authentication request.
        
        :param query_id: The identifier for this request
        :param destination: Where the request should be sent.
        :param service_url: Where the reply should be sent.
        :param spentityid: The entity identifier for this service.
        :param my_name: The name of this service.
        :param vorg: The vitual organization the service belongs to.
        :param scoping: The scope of the request
        :param log: A service to which logs should be written
        :param sign: Whether the request should be signed or not.
        :param binding: The protocol to use for the Response !!
        :return: <samlp:AuthnRequest> instance

        added: we want additional kw arguments, namely is_passive
        """
        request = samlp.AuthnRequest(
            id= query_id,
            version= VERSION,
            issue_instant= instant(),
            assertion_consumer_service_url= service_url,
            protocol_binding= binding,
            **kwargs
        )

        if destination:
            request.destination = destination
        if my_name:
            request.provider_name = my_name
        if scoping:
            request.scoping = scoping

        # Profile stuff, should be configurable
        if nameid_format == saml.NAMEID_FORMAT_TRANSIENT:
            name_id_policy = samlp.NameIDPolicy(allow_create="true",
                                                format=nameid_format)
        else:
            name_id_policy = samlp.NameIDPolicy(format=nameid_format)

        if vorg:
            try:
                name_id_policy.sp_name_qualifier = vorg
                name_id_policy.format = saml.NAMEID_FORMAT_PERSISTENT
            except KeyError:
                pass

        if sign is None:
            sign =  self.authn_requests_signed

        if sign:
            request.signature = pre_signature_part(request.id,
                                                    self.sec.my_cert, 1)
            to_sign = [(class_name(request), request.id)]
        else:
            to_sign = []

        request.name_id_policy = name_id_policy
        request.issuer = self._issuer(spentityid)

        logger.info("REQUEST: %s" % request)

        return signed_instance_factory(request, self.sec, to_sign)


    def authn(self, location, session_id, vorg="", scoping=None, log=None,
                sign=None, binding=BINDING_HTTP_POST,
                service_url_binding=None, **kwargs):
        """
        Construct a Authentication Request

        :param location: The URL of the destination
        :param session_id: The ID of the session
        :param vorg: The virtual organization if any that is involved
        :param scoping: How the request should be scoped, default == Not
        :param log: A log function to use for logging
        :param sign: If the request should be signed
        :param binding: The binding to use, default = HTTP POST
        :return: An AuthnRequest instance
        """
        spentityid = self.config.entityid
        if service_url_binding is None:
            service_url = self.service_url(binding)
        else:
            service_url = self.service_url(service_url_binding)
        if binding == BINDING_PAOS:
            my_name = None
            location = None
        else:
            my_name = self._my_name()


        logger.info("spentityid: %s" % spentityid)
        logger.info("service_url: %s" % service_url)
        logger.info("my_name: %s" % my_name)

        return self.authn_request(session_id, location, service_url,
                                  spentityid, my_name, vorg, scoping, log,
                                  sign, binding=service_url_binding or binding, **kwargs)


    def authenticate(self, entityid=None, relay_state="",
                     binding=BINDING_HTTP_REDIRECT,
                     log=None, vorg="", scoping=None, sign=None, **kwargs):
        """ Makes an authentication request.

        :param entityid: The entity ID of the IdP to send the request to
        :param relay_state: To where the user should be returned after
            successfull log in.
        :param binding: Which binding to use for sending the request
        :param log: Where to write log messages
        :param vorg: The entity_id of the virtual organization I'm a member of
        :param scoping: For which IdPs this query are aimed.
        :param sign: Whether the request should be signed or not.
        :return: AuthnRequest response
        """
        destination = self._sso_location(entityid, binding=binding)
        session_id = sid()

        _req_str = "%s" % self.authn(destination, session_id, vorg, scoping, log,
                                       sign, **kwargs)

        logger.info("AuthNReq: %s" % _req_str)

        info = self.apply_binding(binding, _req_str, destination, relay_state)
        return session_id, info


    def make_logout_response(self, idp_entity_id, request_id,
                             status_code, binding=BINDING_HTTP_REDIRECT):
        """ 
        XXX There were issues with an explicit closing tag on 
        StatusCode. Check wether we still need this. XXX
        Constructs a LogoutResponse

        :param idp_entity_id: The entityid of the IdP that want to do the
            logout
        :param request_id: The Id of the request we are replying to
        :param status_code: The status code of the response
        :param binding: The type of binding that will be used for the response
        :return: A LogoutResponse instance
        """
        srvs = self.metadata.single_logout_service(idp_entity_id, binding, "idpsso")

        destination = destinations(srvs)[0]
        logger.info("destination to provider: %s" % destination)

        status = samlp.Status(
            status_code=samlp.StatusCode(value=status_code, text='\n'),
            status_message=samlp.StatusMessage(text='logout success')
            )

        response = samlp.LogoutResponse(
            id=sid(),
            version=VERSION,
            issue_instant=instant(),
            destination=destination,
            issuer=saml.Issuer(text=self.config.entityid,
                                format=saml.NAMEID_FORMAT_ENTITY),
            in_response_to=request_id,
            status=status,
            )

        return response, destination


    def http_redirect_logout_request_check_session_index(self, get, session_index, log=None):
        """ Deal with a LogoutRequest received through HTTP redirect

        :param get: The request as a dictionary 
        :param subject_id: the id of the current logged user
        :return: a tuple with a list of header tuples (presently only location)
        """
        msg = {}

        try:
            saml_request = get['SAMLRequest']
        except KeyError:
            return None

        if saml_request:
            xml = decode_base64_and_inflate(saml_request)
            logger.info('logout request: %s' % xml)
            request = samlp.logout_request_from_string(xml)
            logger.debug(request)

            if request.session_index[0].text == session_index:
                status = samlp.STATUS_SUCCESS
            else:
                status = samlp.STATUS_REQUEST_DENIED

            response, destination = self .make_logout_response(
                                                        request.issuer.text,
                                                        request.id,
                                                        status)

            logger.info("RESPONSE: {0:>s}".format(response))

            if 'RelayState' in get:
                rstate = get['RelayState']
            else:
                rstate = ""
            msg = http_redirect_message(str(response),
                                        destination,
                                        rstate, 'SAMLResponse')

        return msg


    def artifact2destination(self, artifact, descriptor):
        """
        XXX taken from pysaml2 1.0.3 (broken in 1.0.2). Remove when upgrading

        Translate an artifact into a receiver location

        :param artifact: The Base64 encoded SAML artifact
        :return:
        """

        _art = base64.b64decode(artifact)

        assert _art[:2] == ARTIFACT_TYPECODE

        try:
            endpoint_index = str(int(_art[2:4]))
        except ValueError:
            endpoint_index = str(int(hexlify(_art[2:4])))
        entity = self.sourceid[_art[4:24]]

        destination = None
        for desc in entity["%s_descriptor" % descriptor]:
            for srv in desc["artifact_resolution_service"]:
                if srv["index"] == endpoint_index:
                    destination = srv["location"]
                    break

        return destination

    def send(self, url, method="GET", **kwargs):
        """
        XXX broken in pysaml2 1.0.2. Remove when upgrading
        """
        _kwargs = copy.copy(self.request_args)
        if kwargs:
            _kwargs.update(kwargs)

        if self.cookiejar:
            _cd = self.cookies(url)
            if _cd:
                _kwargs["cookies"] = _cd

        if self.user and self.passwd:
            _kwargs["auth"] = (self.user, self.passwd)

        if "headers" in _kwargs and isinstance(_kwargs["headers"], list):
            if DICT_HEADERS:
                # requests.request wants a dict of headers, not a list of tuples
                _kwargs["headers"] = dict(_kwargs["headers"])

        logger.debug("%s to %s" % (method, url))
        for arg in ["cookies", "data", "auth"]:
            try:
                logger.debug("%s: %s" % (arg.upper(), _kwargs[arg]))
            except KeyError:
                pass
        r = requests.request(method, url, **_kwargs)
        logger.debug("Response status: %s" % r.status_code)

        try:
            self.set_cookie(SimpleCookie(r.headers["set-cookie"]), r)
        except (AttributeError, KeyError):
            pass

        return r

    def use_soap(self, request, destination="", soap_headers=None, sign=False):
        """
        XXX use SOAP 1.1 for now
        Construct the necessary information for using SOAP+POST

        :param request:
        :param destination:
        :param soap_headers:
        :param sign:
        :return: dictionary
        """
        headers = [("content-type", "text/xml")]

        soap_message = make_soap_enveloped_saml_thingy(request, soap_headers)

        logger.debug("SOAP message: %s" % soap_message)

        if sign and self.sec:
            _signed = self.sec.sign_statement(soap_message,
                                              class_name=class_name(request),
                                              node_id=request.id)
            soap_message = _signed

        return {"url": destination, "method": "POST",
                "data": soap_message, "headers": headers}


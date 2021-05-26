import logging
import requests
from saml2.client import Saml2Client as BaseClient
from saml2.s_utils import sid, decode_base64_and_inflate
from saml2 import saml, samlp, VERSION
from saml2.time_util import instant
from saml2.pack import http_redirect_message
from saml2.mdstore import destinations
from saml2 import BINDING_HTTP_REDIRECT

logger = logging.getLogger(__name__)

if requests.__version__ < "2.0.0":
    DICT_HEADERS = False
else:
    DICT_HEADERS = True


class Saml2Client(BaseClient):

    """
    extensions and changes for pysaml2.client.Saml2Client
    """

    def make_logout_response(
        self, idp_entity_id, request_id, status_code, binding=BINDING_HTTP_REDIRECT
    ):
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
            status_code=samlp.StatusCode(value=status_code, text="\n"),
            status_message=samlp.StatusMessage(text="logout success"),
        )

        response = samlp.LogoutResponse(
            id=sid(),
            version=VERSION,
            issue_instant=instant(),
            destination=destination,
            issuer=saml.Issuer(
                text=self.config.entityid, format=saml.NAMEID_FORMAT_ENTITY
            ),
            in_response_to=request_id,
            status=status,
        )

        return response, destination

    def http_redirect_logout_request_check_session_index(
        self, get, session_index, log=None
    ):
        """Deal with a LogoutRequest received through HTTP redirect

        :param get: The request as a dictionary
        :param subject_id: the id of the current logged user
        :return: a tuple with a list of header tuples (presently only location)
        """
        msg = {}

        try:
            saml_request = get["SAMLRequest"]
        except KeyError:
            return None

        if saml_request:
            xml = decode_base64_and_inflate(saml_request)
            logger.info("logout request: %s" % xml)
            request = samlp.logout_request_from_string(xml)
            logger.debug(request)

            if request.session_index[0].text == session_index:
                status = samlp.STATUS_SUCCESS
            else:
                status = samlp.STATUS_REQUEST_DENIED

            response, destination = self.make_logout_response(
                request.issuer.text, request.id, status
            )
            logger.info("RESPONSE: {}".format(response))

            if "RelayState" in get:
                rstate = get["RelayState"]
            else:
                rstate = ""
            msg = http_redirect_message(
                str(response), destination, rstate, "SAMLResponse"
            )

        return msg

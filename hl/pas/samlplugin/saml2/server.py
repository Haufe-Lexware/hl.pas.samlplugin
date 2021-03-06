#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2009-2011 Umeå University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contains classes and functions that a SAML2.0 Identity provider (IdP) 
or attribute authority (AA) may use to conclude its tasks.
"""
import logging
import os

import shelve
import memcache
from saml2.eptid import EptidShelve, Eptid
from saml2.mongo_store import IdentMDB, SessionStorageMDB, EptidMDB
from saml2.sdb import SessionStorage
from saml2.schema import soapenv

from saml2.samlp import NameIDMappingResponse
from saml2.entity import Entity

from saml2 import saml, element_to_extension_element
from saml2 import class_name
from saml2 import BINDING_HTTP_REDIRECT

from saml2.request import AuthnRequest
from saml2.request import AssertionIDRequest
from saml2.request import AttributeQuery
from saml2.request import NameIDMappingRequest
from saml2.request import AuthzDecisionQuery
from saml2.request import AuthnQuery

from saml2.s_utils import MissingValue, Unknown, rndstr

from saml2.sigver import pre_signature_part, signed_instance_factory

from saml2.assertion import Assertion
from saml2.assertion import Policy
from saml2.assertion import restriction_from_attribute_spec
from saml2.assertion import filter_attribute_value_assertions

from saml2.ident import IdentDB
from saml2.profile import ecp

logger = logging.getLogger(__name__)


class Server(Entity):
    """ A class that does things that IdPs or AAs do """
    def __init__(self, config_file="", config=None, cache=None, stype="idp",
                 symkey=""):
        Entity.__init__(self, stype, config, config_file)
        self.init_config(stype)
        self.cache = cache
        self.ticket = {}
        #
        self.session_db = self.choose_session_storage()
        # Needed for
        self.symkey = symkey
        self.seed = rndstr()
        self.iv = os.urandom(16)
        self.eptid = None

    def support_AssertionIDRequest(self):
        return True

    def support_AuthnQuery(self):
        return True

    def choose_session_storage(self):
        _spec = self.config.getattr("session_storage", "idp")
        if not _spec:
            return SessionStorage()
        elif isinstance(_spec, basestring):
            if _spec.lower() == "memory":
                return SessionStorage()
        else:  # Should be tuple
            typ, data = _spec
            if typ.lower() == "mongodb":
                return SessionStorageMDB(data)

        raise NotImplementedError("No such storage type implemented")

    def init_config(self, stype="idp"):
        """ Remaining init of the server configuration 
        
        :param stype: The type of Server ("idp"/"aa")
        """
        if stype == "aa":
            return
        
        # subject information is stored in a database
        # default database is in memory which is OK in some setups
        dbspec = self.config.getattr("subject_data", "idp")
        idb = None
        typ = ""
        if not dbspec:
            idb = {}
        elif isinstance(dbspec, basestring):
            idb = shelve.open(dbspec, writeback=True)
        else:  # database spec is a a 2-tuple (type, address)
            #print >> sys.stderr, "DBSPEC: %s" % (dbspec,)
            (typ, addr) = dbspec
            if typ == "shelve":
                idb = shelve.open(addr, writeback=True)
            elif typ == "memcached":
                idb = memcache.Client(addr)
            elif typ == "dict":  # in-memory dictionary
                idb = {}
            elif typ == "mongodb":
                self.ident = IdentMDB(addr)

        if typ == "mongodb":
            pass
        elif idb is not None:
            self.ident = IdentDB(idb)
        elif dbspec:
            raise Exception("Couldn't open identity database: %s" %
                            (dbspec,))

        dbspec = self.config.getattr("edu_person_targeted_id", "idp")
        if not dbspec:
            pass
        else:
            typ = dbspec[0]
            addr = dbspec[1]
            secret = dbspec[2]
            if typ == "shelve":
                self.eptid = EptidShelve(secret, addr)
            elif typ == "mongodb":
                self.eptid = EptidMDB(secret, addr, *dbspec[3:])
            else:
                self.eptid = Eptid(secret)

    def wants(self, sp_entity_id, index=None):
        """ Returns what attributes the SP requires and which are optional
        if any such demands are registered in the Metadata.

        :param sp_entity_id: The entity id of the SP
        :param index: which of the attribute consumer services its all about
        :return: 2-tuple, list of required and list of optional attributes
        """
        return self.metadata.attribute_requirement(sp_entity_id, index)

    # -------------------------------------------------------------------------

    def parse_authn_request(self, enc_request, binding=BINDING_HTTP_REDIRECT):
        """Parse a Authentication Request
        
        :param enc_request: The request in its transport format
        :param binding: Which binding that was used to transport the message
            to this entity.
        :return: A dictionary with keys:
            consumer_url - as gotten from the SPs entity_id and the metadata
            id - the id of the request
            sp_entity_id - the entity id of the SP
            request - The verified request
        """

        return self._parse_request(enc_request, AuthnRequest,
                                   "single_sign_on_service", binding)

    def parse_attribute_query(self, xml_string, binding):
        """ Parse an attribute query
        
        :param xml_string: The Attribute Query as an XML string
        :param binding: Which binding that was used for the request
        :return: A query instance
        """

        return self._parse_request(xml_string, AttributeQuery,
                                   "attribute_service", binding)

    def parse_authz_decision_query(self, xml_string, binding):
        """ Parse an attribute query

        :param xml_string: The Authz decision Query as an XML string
        :return: Query instance
        """

        return self._parse_request(xml_string, AuthzDecisionQuery,
                                   "authz_service", binding)

    def parse_assertion_id_request(self, xml_string, binding):
        """ Parse an assertion id query

        :param xml_string: The AssertionIDRequest as an XML string
        :return: Query instance
        """

        return self._parse_request(xml_string, AssertionIDRequest,
                                   "assertion_id_request_service", binding)

    def parse_authn_query(self, xml_string, binding):
        """ Parse an authn query

        :param xml_string: The AuthnQuery as an XML string
        :return: Query instance
        """

        return self._parse_request(xml_string, AuthnQuery,
                                   "authn_query_service", binding)

    def parse_name_id_mapping_request(self, xml_string, binding):
        """ Parse a nameid mapping request

        :param xml_string: The NameIDMappingRequest as an XML string
        :return: Query instance
        """

        return self._parse_request(xml_string, NameIDMappingRequest,
                                   "name_id_mapping_service", binding)

    # ------------------------------------------------------------------------

    # ------------------------------------------------------------------------

    def _authn_response(self, in_response_to, consumer_url,
                        sp_entity_id, identity=None, name_id=None,
                        status=None, authn=None, issuer=None, policy=None,
                        sign_assertion=False, sign_response=False):
        """ Create a response. A layer of indirection.
        
        :param in_response_to: The session identifier of the request
        :param consumer_url: The URL which should receive the response
        :param sp_entity_id: The entity identifier of the SP
        :param identity: A dictionary with attributes and values that are
            expected to be the bases for the assertion in the response.
        :param name_id: The identifier of the subject
        :param status: The status of the response
        :param authn: A dictionary containing information about the
            authn context.
        :param issuer: The issuer of the response
        :param sign_assertion: Whether the assertion should be signed or not
        :param sign_response: Whether the response should be signed or not
        :return: A response instance
        """

        to_sign = []
        args = {}
        if identity:
            _issuer = self._issuer(issuer)
            ast = Assertion(identity)
            if policy is None:
                policy = Policy()
            try:
                ast.apply_policy(sp_entity_id, policy, self.metadata)
            except MissingValue, exc:
                return self.create_error_response(in_response_to, consumer_url,
                                                  exc, sign_response)

            if authn:  # expected to be a dictionary
                if "decl" in authn:
                    assertion = ast.construct(sp_entity_id, in_response_to,
                                              consumer_url, name_id,
                                              self.config.attribute_converters,
                                              policy, issuer=_issuer,
                                              authn_decl=authn["decl"],
                                              authn_auth=authn["authn_auth"])
                else:
                    assertion = ast.construct(sp_entity_id, in_response_to,
                                              consumer_url, name_id,
                                              self.config.attribute_converters,
                                              policy, issuer=_issuer,
                                              authn_class=authn["class_ref"],
                                              authn_auth=authn["authn_auth"])
            else:
                assertion = ast.construct(sp_entity_id, in_response_to,
                                          consumer_url, name_id,
                                          self.config.attribute_converters,
                                          policy, issuer=_issuer)

            if sign_assertion:
                assertion.signature = pre_signature_part(assertion.id,
                                                         self.sec.my_cert, 1)
                # Just the assertion or the response and the assertion ?
                to_sign = [(class_name(assertion), assertion.id)]

            # Store which assertion that has been sent to which SP about which
            # subject.

            # self.cache.set(assertion.subject.name_id.text,
            #                 sp_entity_id, {"ava": identity, "authn": authn},
            #                 assertion.conditions.not_on_or_after)

            args["assertion"] = assertion

            if self.support_AssertionIDRequest() or self.support_AuthnQuery():
                self.session_db.store_assertion(assertion, to_sign)

        return self._response(in_response_to, consumer_url, status, issuer,
                              sign_response, to_sign, **args)
                        
    # ------------------------------------------------------------------------

    #noinspection PyUnusedLocal
    def create_attribute_response(self, identity, in_response_to, destination,
                                  sp_entity_id, userid="", name_id=None,
                                  status=None, issuer=None,
                                  sign_assertion=False, sign_response=False,
                                  attributes=None, **kwargs):
        """ Create an attribute assertion response.
        
        :param identity: A dictionary with attributes and values that are
            expected to be the bases for the assertion in the response.
        :param in_response_to: The session identifier of the request
        :param destination: The URL which should receive the response
        :param sp_entity_id: The entity identifier of the SP
        :param userid: A identifier of the user
        :param name_id: The identifier of the subject
        :param status: The status of the response
        :param issuer: The issuer of the response
        :param sign_assertion: Whether the assertion should be signed or not
        :param sign_response: Whether the whole response should be signed
        :param attributes:
        :param kwargs: To catch extra keyword arguments
        :return: A response instance
        """

        policy = self.config.getattr("policy", "aa")

        if not name_id and userid:
            try:
                name_id = self.ident.construct_nameid(userid, policy,
                                                      sp_entity_id)
                logger.warning("Unspecified NameID format")
            except Exception:
                pass

        to_sign = []
        args = {}
        if identity:
            _issuer = self._issuer(issuer)
            ast = Assertion(identity)
            if policy:
                ast.apply_policy(sp_entity_id, policy, self.metadata)
            else:
                policy = Policy()

            if attributes:
                restr = restriction_from_attribute_spec(attributes)
                ast = filter_attribute_value_assertions(ast)

            assertion = ast.construct(sp_entity_id, in_response_to,
                                      destination, name_id,
                                      self.config.attribute_converters,
                                      policy, issuer=_issuer)

            if sign_assertion:
                assertion.signature = pre_signature_part(assertion.id,
                                                         self.sec.my_cert, 1)
                # Just the assertion or the response and the assertion ?
                to_sign = [(class_name(assertion), assertion.id)]

            args["assertion"] = assertion

        return self._response(in_response_to, destination, status, issuer,
                              sign_response, to_sign, **args)

    # ------------------------------------------------------------------------

    def create_authn_response(self, identity, in_response_to, destination,
                              sp_entity_id, name_id_policy=None, userid=None,
                              name_id=None, authn=None, issuer=None,
                              sign_response=False, sign_assertion=False,
                              **kwargs):
        """ Constructs an AuthenticationResponse

        :param identity: Information about an user
        :param in_response_to: The identifier of the authentication request
            this response is an answer to.
        :param destination: Where the response should be sent
        :param sp_entity_id: The entity identifier of the Service Provider
        :param name_id_policy: How the NameID should be constructed
        :param userid: The subject identifier
        :param authn: Information about the authentication context
        :param issuer: Issuer of the response
        :param sign_assertion: Whether the assertion should be signed or not.
        :param sign_response: Whether the response should be signed or not.
        :return: A response instance
        """

        policy = self.config.getattr("policy", "idp")

        if not name_id:
            try:
                nid_formats = []
                for _sp in self.metadata[sp_entity_id]["spsso_descriptor"]:
                    if "name_id_format" in _sp:
                        nid_formats.extend([n["text"] for n in
                                            _sp["name_id_format"]])
                try:
                    snq = name_id_policy.sp_name_qualifier
                except AttributeError:
                    snq = sp_entity_id

                _nids = self.ident.find_nameid(userid, sp_name_qualifier=snq)
                # either none or one
                if _nids:
                    name_id = _nids[0]
                else:
                    name_id = self.ident.construct_nameid(userid, policy,
                                                          sp_entity_id,
                                                          name_id_policy,
                                                          nid_formats)
            except IOError, exc:
                response = self.create_error_response(in_response_to,
                                                      destination,
                                                      sp_entity_id,
                                                      exc, name_id)
                return ("%s" % response).split("\n")


        try:
            return self._authn_response(in_response_to,  # in_response_to
                                        destination,     # consumer_url
                                        sp_entity_id,    # sp_entity_id
                                        identity,       # identity as dictionary
                                        name_id,
                                        authn=authn,
                                        issuer=issuer,
                                        policy=policy,
                                        sign_assertion=sign_assertion,
                                        sign_response=sign_response)

        except MissingValue, exc:
            return self.create_error_response(in_response_to, destination,
                                              sp_entity_id, exc, name_id)

    def create_authn_request_response(self, identity, in_response_to,
                                      destination, sp_entity_id,
                                      name_id_policy=None, userid=None,
                                      name_id=None, authn=None, authn_decl=None,
                                      issuer=None, sign_response=False,
                                      sign_assertion=False, **kwargs):

        return self.create_authn_response(identity, in_response_to, destination,
                                          sp_entity_id, name_id_policy, userid,
                                          name_id, authn, authn_decl, issuer,
                                          sign_response, sign_assertion)

    #noinspection PyUnusedLocal
    def create_assertion_id_request_response(self, assertion_id, sign=False,
                                             **kwargs):
        """

        :param assertion_id:
        :param sign:
        :return:
        """

        try:
            (assertion, to_sign) = self.session_db.get_assertion(assertion_id)
        except KeyError:
            raise Unknown

        if to_sign:
            if assertion.signature is None:
                assertion.signature = pre_signature_part(assertion.id,
                                                         self.sec.my_cert, 1)

            return signed_instance_factory(assertion, self.sec, to_sign)
        else:
            return assertion

    #noinspection PyUnusedLocal
    def create_name_id_mapping_response(self, name_id=None, encrypted_id=None,
                                        in_response_to=None,
                                        issuer=None, sign_response=False,
                                        status=None, **kwargs):
        """
        protocol for mapping a principal's name identifier into a
        different name identifier for the same principal.
        Done over soap.

        :param name_id:
        :param encrypted_id:
        :param in_response_to:
        :param issuer:
        :param sign_response:
        :param status:
        :return:
        """
        # Done over SOAP

        ms_args = self.message_args()

        _resp = NameIDMappingResponse(name_id, encrypted_id,
                                      in_response_to=in_response_to, **ms_args)

        if sign_response:
            return self.sign(_resp)
        else:
            logger.info("Message: %s" % _resp)
            return _resp

    def create_authn_query_response(self, subject, session_index=None,
                                    requested_context=None, in_response_to=None,
                                    issuer=None, sign_response=False,
                                    status=None, **kwargs):
        """
        A successful <Response> will contain one or more assertions containing
        authentication statements.

        :return:
        """

        margs = self.message_args()
        asserts = []
        for statement in self.session_db.get_authn_statements(
                subject.name_id, session_index, requested_context):

            asserts.append(saml.Assertion(authn_statement=statement,
                                          subject=subject, **margs))

        if asserts:
            args = {"assertion": asserts}
        else:
            args = {}

        return self._response(in_response_to, "", status, issuer,
                              sign_response, to_sign=[], **args)

    # ---------

    def parse_ecp_authn_request(self):
        pass

    def create_ecp_authn_request_response(self, acs_url, identity,
                                          in_response_to, destination,
                                          sp_entity_id, name_id_policy=None,
                                          userid=None, name_id=None, authn=None,
                                          issuer=None, sign_response=False,
                                          sign_assertion=False, **kwargs):

        # ----------------------------------------
        # <ecp:Response
        # ----------------------------------------

        ecp_response = ecp.Response(assertion_consumer_service_url=acs_url)
        header = soapenv.Header()
        header.extension_elements = [element_to_extension_element(ecp_response)]

        # ----------------------------------------
        # <samlp:Response
        # ----------------------------------------

        response = self.create_authn_response(identity, in_response_to,
                                              destination, sp_entity_id,
                                              name_id_policy, userid, name_id,
                                              authn, issuer,
                                              sign_response, sign_assertion)
        body = soapenv.Body()
        body.extension_elements = [element_to_extension_element(response)]

        soap_envelope = soapenv.Envelope(header=header, body=body)

        return "%s" % soap_envelope

import logging
from saml2.attribute_converter import to_local

logger = logging.getLogger('hl.pas.samlplugin')

def get_identity(resp):
    """
    XXX taken from AuthnResponse - we need this for Artifact responses as well
    """
    if not resp.assertion.attribute_statement:
        logger.error("Missing Attribute Statement")
        ava = {}
    else:
        assert len(resp.assertion.attribute_statement) == 1
        _attr_statem = resp.assertion.attribute_statement[0]

        logger.debug("Attribute Statement: %s" % (_attr_statem,))
        for aconv in resp.attribute_converters:
            logger.info("Converts name format: %s" % (aconv.name_format,))

        ava = to_local(resp.attribute_converters, _attr_statem)
    return ava


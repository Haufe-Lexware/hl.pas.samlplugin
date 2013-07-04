from AccessControl.Permissions import manage_users
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService import registerMultiPlugin

import plugin

manage_add_samlplugin_form = PageTemplateFile('browser/add_plugin.pt',
                            globals(), __name__='manage_add_samlplugin_form' )


def manage_add_samlplugin( dispatcher, id, title=None, REQUEST=None ):
    """Add a samlplugin to the PluggableAuthentication Service."""

    sp = plugin.SAML2Plugin( id, title )
    dispatcher._setObject( sp.getId(), sp )

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect( '%s/manage_workspace'
                                      '?manage_tabs_message='
                                      'SAML2Plugin+added.'
                                      % dispatcher.absolute_url() )


def register_samlplugin_plugin():
    try:
        registerMultiPlugin(plugin.SAML2Plugin.meta_type)
    except RuntimeError:
        # make refresh users happy
        pass


def register_samlplugin_plugin_class(context):
    context.registerClass(plugin.SAML2Plugin,
                         permission=manage_users,
                         constructors = (manage_add_samlplugin_form,
                                         manage_add_samlplugin),
                         visibility=None,
                         icon='browser/icon.gif')

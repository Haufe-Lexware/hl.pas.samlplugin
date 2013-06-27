## Script (Python) "check_session"
##bind container=container
##bind context=context
##bind namespace=
##bind script=script
##bind subpath=traverse_subpath
##parameters=came_from=''
from Products.CMFCore.utils import getUtilityByInterfaceName
util = getUtilityByInterfaceName('hl.pas.samlplugin.interfaces.ISAMLSessionCheck')
if came_from:
    context.REQUEST.set('ACTUAL_URL', came_from)
util.checksession(request=context.REQUEST)


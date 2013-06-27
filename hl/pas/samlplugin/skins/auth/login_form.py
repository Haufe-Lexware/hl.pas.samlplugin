## Script (Python) "login_form"
##bind container=container
##bind context=context
##bind namespace=
##bind script=script
##bind subpath=traverse_subpath
##parameters=came_from=''
return context.REQUEST.RESPONSE.redirect('%s/auth?came_from=%s' % (context.portal_url(), came_from))


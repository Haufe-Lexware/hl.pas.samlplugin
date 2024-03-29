# -*- coding: utf-8 -*-
import os
from setuptools import setup, find_packages


def read(*rnames):
    return open(os.path.join(os.path.dirname(__file__), *rnames)).read()

version = '2.0.dev0'

long_description = (
    read('README.rst')
    + '\n' +
    read('docs', 'HISTORY.txt')
    + '\n' +
    'Contributors\n'
    '************\n'
    + '\n' +
    read('docs', 'CONTRIBUTORS.txt')
    + '\n' +
    'Download\n'
    '********\n')

tests_require = ['zope.testing']

setup(name='hl.pas.samlplugin',
      version=version,
      description="SAML2 authentication for Zope",
      long_description=long_description,
      # Get more strings from
      # http://pypi.python.org/pypi?:action=list_classifiers
      classifiers=[
        'Framework :: Zope2',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        ],
      keywords='saml2 zope pas',
      author='Thomas Schorr',
      author_email='thomas.schorr@haufe-lexware.com',
      url='https://github.com/Haufe-Lexware/hl.pas.samlplugin',
      license='Apache 2.0',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['hl', 'hl.pas'],
      include_package_data=True,
      zip_safe=False,
      install_requires=['setuptools',
                        # -*- Extra requirements: -*-
                        'zope.app.container',
                        'Products.PluggableAuthService',
                        'requests',
                        'pysaml2',
                        ],
      tests_require=tests_require,
      extras_require=dict(tests=tests_require),
      test_suite='hl.pas.samlplugin.tests.test_saml2',
      entry_points="""
      # -*- entry_points -*-

      [z3c.autoinclude.plugin]
      target = plone
      """,
      )

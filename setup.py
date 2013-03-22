import os
import sys

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True
    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import pytest
        pytest.main(self.test_args)
        result = pytest.main(self.test_args)
        sys.exit(result)

here = os.path.abspath(os.path.dirname(__file__))
README = ''#open(os.path.join(here, 'README.md')).read()
CHANGES = ''#open(os.path.join(here, 'CHANGES.txt')).read()

requires = [
    'pyramid'
    , 'sqlalchemy'
    , 'cryptacular'
    , 'colander'
    , 'deform'
    , 'pyramid_deform'
    , 'transaction'
    , 'zope.sqlalchemy'
    , 'pystache'
    , 'pyramid_mailer'
    , 'beaker'
    , 'pyramid_beaker'
    , 'hem'
    , 'psycopg2'
]

setup(name='horus'
      , version='0.0.29'
      , description='Generic user registration for pyramid'
      , long_description=README + '\n\n' +  CHANGES
      , classifiers=[
            'Intended Audience :: Developers'
            , 'License :: OSI Approved :: BSD License'
            , 'Operating System :: OS Independent'
            , 'Programming Language :: Python'
            , 'Topic :: Internet :: WWW/HTTP :: Dynamic Content'
            , 'Topic :: Software Development :: Libraries :: Python Modules'
      ]
      , author='John Anderson'
      , author_email='sontek@gmail.com'
      , url='https://github.com/sontek/horus'
      , keywords='pyramid'
      , license='BSD'
      , packages=find_packages()
      , include_package_data=True
      , zip_safe=False
      , install_requires=requires
      , tests_require=requires + ['pytest', 'mock', 'webtest', 'pytest-cov']
      , cmdclass = {'test': PyTest}
      , test_suite='horus'
      , message_extractors = {
            'horus': [
                ('**.py', 'python', None),
                ('**/templates/**.html', 'mako', None),
                ('**/templates/**.mako', 'mako', None),
            ]
        }

)


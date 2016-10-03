#!/usr/bin/env python3

import re
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

__version__ = None
__license__ = None
__author__ = None
exec(open('hlc/_meta.py').read())
author = re.search(r'^(?P<name>[^<]+) <(?P<email>.*)>$', __author__)

# https://docs.python.org/3/distutils/apiref.html#distutils.core.setup
# https://setuptools.readthedocs.io/en/latest/setuptools.html
setup(
    name='hlc',
    version=__version__,
    description='Host list converter supporting hosts(5), ethers(5) and other formats',
    long_description=open(os.path.join(here, 'README.rst')).read(),
    url='https://github.com/ypid/hlc',
    author=author.group('name'),
    author_email=author.group('email'),
    # Basically redundant but when not specified `./setup.py --maintainer` will
    # return "UNKNOWN".
    maintainer=author.group('name'),
    maintainer_email=author.group('email'),
    license=__license__,
    classifiers=(
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: DFSG approved',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        #  'Programming Language :: Python :: 3.2',
        #  'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        #  'Programming Language :: Python :: 3.6',
        'Topic :: System :: Systems Administration',
        'Topic :: Text Processing',
    ),
    keywords="workstations host list converter ethers mac-address",
    packages=find_packages(),
    install_requires=[
        # Debian packages: python3-netaddr
        # jessie-backports: python3-netaddr
        'netaddr>=0.7.18',
    ],
    extras_require={
        'test': ['nose', 'nose2', 'tox'],
    },
    entry_points={
        'console_scripts': [
            'hlc = hlc.cli:main',
        ],
    },
)

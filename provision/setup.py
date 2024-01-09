import os
import sys
import tokenize
from gitversion.gitversion import get_git_version
from setuptools import setup, find_packages

file_dir = os.path.dirname(__file__)
sys.path.append(file_dir)
os.chdir(os.path.abspath(file_dir))

try:
    _detect_encoding = tokenize.detect_encoding
except AttributeError:
    pass
else:
    def detect_encoding(readline):
        try:
            return _detect_encoding(readline)
        except SyntaxError:
            return 'latin-1', []

    tokenize.detect_encoding = detect_encoding

setup(
    name='acc_provision',
    version='6.0.3.2',
    description='Tool to provision ACI for ACI Containers Controller  Build info: ' + get_git_version(),
    author="Cisco Systems, Inc.",
    author_email="apicapi@noironetworks.com",
    url='http://github.com/noironetworks/acc-provision/',
    license="http://www.apache.org/licenses/LICENSE-2.0",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    scripts=['bin/acikubectl'],
    entry_points={
        'console_scripts': [
            'acc-provision=acc_provision.acc_provision:main',
            'acc-retrieve-cert=acc_provision.acc_retrieve_cert:main',
        ]
    },
    install_requires=[
          'requests',
          'pyyaml',
          'jinja2',
          'pyopenssl',
          'MarkupSafe',
          'boto3',
          'ruamel.yaml',
    ],
)

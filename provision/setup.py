import os
import sys
import tokenize
from gitversion.gitversion import get_git_version
from setuptools import setup, find_packages

file_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(file_dir)
os.chdir(file_dir)

with open(os.path.join(file_dir, 'README.md'), encoding='utf-8') as readme:
    long_description = readme.read()

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
    version='6.1.1.7',
    description='Tool to provision ACI for ACI Containers Controller  Build info: ' + get_git_version(),
    long_description=long_description,
    long_description_content_type='text/markdown',
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
          'ruamel.yaml',
          'packaging',
    ],
)

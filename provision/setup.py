from setuptools import setup, find_packages
import os, sys 
file_dir = os.path.dirname(__file__)
sys.path.append(file_dir)
from gitversion.gitversion import get_git_version

setup(
    name='acc_provision',
    version='4.1.1.5',
    description='Tool to provision ACI for ACI Containers Controller  Build info: ' + get_git_version(),
    author="Cisco Systems, Inc.",
    author_email="apicapi@noironetworks.com",
    url='http://github.com/noironetworks/acc-provision/',
    license="http://www.apache.org/licenses/LICENSE-2.0",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'acc-provision=acc_provision.acc_provision:main',
        ]
    },
    install_requires=[
          'requests',
          'pyyaml',
          'jinja2',
          'pyopenssl',
    ],
)

#
# Minimal Makefile to run aci-containers-provisioning tests
#

.EXPORT_ALL_VARIABLES:
# because fake apic server is insecure
PYTHONWARNINGS = ignore:Unverified HTTPS request

dist: test
	python setup.py sdist

test:
	flake8 --builtins="unicode" --ignore E501,E731,E741,W504 acc_provision
	python -m pytest acc_provision

stop-on-err:
	python -m pytest -x acc_provision

clean:
	rm -rf dist acc_provision.egg-info acc_provision/__pycache__ testdata/tmp-*

upload: clean
	python setup.py --description
	python setup.py sdist upload

upload-twine: clean
	python setup.py --description
	python setup.py sdist bdist_wheel
	twine upload --repository pypi dist/*

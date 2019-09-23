#!/usr/bin/env python

from __future__ import print_function, unicode_literals

import argparse
import base64
import json
import subprocess
import sys


KUBECONFIG = None


def info(msg):
    print("INFO: " + msg, file=sys.stderr)


def err(msg):
    print("ERR:  " + msg, file=sys.stderr)


def kubectl(kind, name, namespace=None):
    ret = None
    cmd = ['kubectl', 'get', '-o', 'json']
    cmd.extend([kind, name])
    if namespace:
        cmd.extend(['-n', namespace])
    if KUBECONFIG:
        cmd.extend(['--kubeconfig', KUBECONFIG])
    retstr = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    if retstr:
        ret = json.loads(retstr).get('data')
    return ret


def get_secret(name, namespace, *keys):
    ret = []
    data = kubectl('secret', name, namespace)
    decode = lambda k: data.get(k) and base64.b64decode(data[k].decode("ascii"))
    if keys:
        ret = map(decode, keys)
    return ret


def get_sysid(name, namespace):
    ret = None
    data = kubectl('configmap', name, namespace)
    if data and data.get('controller-config'):
        config = json.loads(data.get('controller-config'))
        if config:
            ret = config.get('aci-prefix')
    return ret


def retrieve_certs(sysid, name, namespace=None):
    key, crt = get_secret(name, namespace, 'user.key', 'user.crt')
    for k, v in zip(['key', 'crt'], [key, crt]):
        if v:
            fname = 'user-%s.%s' % (sysid, k)
            try:
                with open(fname, "w") as fd:
                    fd.write(v)
            except Exception:
                err("Could not write: " + fname)
                return
            info("Retrieved: " + fname)


class CustomFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        ret = super(CustomFormatter, self)._format_action_invocation(action)
        ret = ret.replace(' ,', ',')
        ret = ret.replace(' file,', ',')
        return ret


def parse_args():
    parser = argparse.ArgumentParser(
        description='Retrieve certificate and key added by acc-provision',
        formatter_class=CustomFormatter,
    )
    parser.add_argument(
        '-k', '--kubeconfig', default=None, metavar='file',
        help='Path to the kubeconfig file if different from default')

    return parser.parse_args()


def main(args=None):
    args = parse_args()

    # This is ugly and temporary
    global KUBECONFIG
    if args.kubeconfig:
        KUBECONFIG = args.kubeconfig
        try:
            open(KUBECONFIG, "r").read()
        except Exception as e:
            err(repr(e))
            return
        info("Using kubeconfig: " + KUBECONFIG)

    namespace_os = 'aci-containers-system'
    namespace_kube = 'kube-system'
    config_name = 'aci-containers-config'
    secret_name = 'aci-user-cert'

    try:
        sysid = get_sysid(config_name, namespace_os)
        if sysid:
            retrieve_certs(sysid, secret_name, namespace_os)
    except Exception:
        try:
            sysid = get_sysid(config_name, namespace_kube)
            if sysid:
                retrieve_certs(sysid, secret_name, namespace_kube)
        except Exception as e:
            err(repr(e))
            err("Couldn't find the required secret files in either aci-containers-system or kube-system.")


if __name__ == '__main__':
    main()

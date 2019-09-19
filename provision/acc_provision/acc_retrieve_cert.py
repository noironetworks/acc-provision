#!/usr/bin/env python

import base64
import json
import subprocess


def kubectl(kind, name, namespace=None):
    ret = None
    cmd = ['kubectl', 'get', '-o', 'json']
    cmd.extend([kind, name])
    if namespace:
        cmd.extend(['-n', namespace])
    retstr = subprocess.check_output(cmd)
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
            with open(fname, "w") as fd:
                fd.write(v)


def main():
    namespace = 'aci-containers-system'
    config_name = 'aci-containers-config'
    secret_name = 'aci-user-cert'

    try:
        sysid = get_sysid(config_name, namespace)
        if sysid:
            retrieve_certs(sysid, secret_name, namespace)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()

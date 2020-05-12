'''
Generate certificate and key

@author:     Jacob Antony Vaikath

@copyright:  2017 Cisco Systems. All rights reserved.
@contact:    jantonyv@cisco.com
'''

import subprocess
import logging
import argparse
import sys
import os
import requests
import json
import shutil
import stat

SERIAL_NUMBER = ''
COMMON_NAME = ''
PASSPHRASE = ''
REQUEST_TYPE = ''
MY_NODE_IDIP = ''
MY_CHASSIS_ID = ''
MY_SN = ''

KEY_PEM = 'temp.key.pem'
CSR_PEM = 'temp.csr.pem'
SIGN = 'temp.sign'
REST_COOKIE = 'cookie'

FINAL_CRT = 'server.crt'
FINAL_KEY = 'server.key'
FINAL_CA = 'cacert.crt'
FINAL_CRT_DER = 'server.crt.der'
FINAL_KEY_DER = 'server.key.der'
FINAL_CA_DER = 'cacert.crt.der'
FINAL_P8 = 'server.p8'
FINAL_P12 = 'server.p12'
EXPORT_PASS = 'ins3965!'
FINAL_BLOB = 'blob.txt'

# Copies to support naming as per cert generation infra
CERT_COPY = [(FINAL_P8, 'server8.key'), (FINAL_CA, 'ApicCa.crt')]

INOPENSSL_CONF_FILE = 'gen.cnf'
INOPENSSL_CONF_TEMPLATE = '''
[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha512
prompt              = no

[ req_distinguished_name ]
commonName                      = {common_name}
'''
INOPENSSL_SERIAL_CONF_TEMPLATE = '''
serialNumber                    = {serial_number}
'''

logger = None

session = requests.Session()
retry = requests.packages.urllib3.util.retry.Retry(total=3, read=3, connect=3, backoff_factor=0.3, status_forcelist=(500, 502, 503))
session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retry))


def set_logger(logdir, logfile):
    if not os.path.isdir(logdir):
        print('Log directory %s does not exist') % logdir
        sys.exit(1)
    logpath = logdir + '/' + logfile
    try:
        if not os.path.exists(logpath):
            print("Log file {} does not exist yet. Create file".format(logpath))
            with open(logpath, 'w'):
                pass
        mask = stat.S_IROTH | stat.S_IRGRP
        if os.stat(logpath).st_mode & mask != mask:
            print('Set read permission for %s') % logpath
            os.chmod(logpath, 0o666)
    except Exception as e:
        print("Exception {} setting logger".format(e))
        pass
    logger = logging.getLogger(__name__)
    hdlr = logging.FileHandler(logpath)
    formatter = logging.Formatter('%(asctime)s | %(process)d | %(levelname)s | %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)
    return logger


def run(cmd):
    shell = True if type(cmd) is str else False
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=shell)
    out = proc.communicate()[0].strip()
    logger.info('>> %s | RETURN: %d' % (cmd, proc.returncode))
    if proc.returncode != 0:
        logger.error(out)
    return proc.returncode, out


def cleanup(keep_final=True):
    tmp_files = [KEY_PEM, CSR_PEM, SIGN, INOPENSSL_CONF_FILE]
    final_files = [FINAL_CRT, FINAL_KEY, FINAL_CA, FINAL_P8, FINAL_CRT_DER, FINAL_KEY_DER, FINAL_CA_DER, FINAL_P8, FINAL_P12, FINAL_BLOB]
    if not keep_final:
        tmp_files.extend(final_files)
    removed_files = []
    for tmp_file in tmp_files:
        try:
            os.remove(tmp_file)
            removed_files.append(tmp_file)
        except OSError:
            pass
    logger.info('Removed files: %s', ' '.join(removed_files))


def generate_pair(nodeip, phrase, cn):
    '''Generates a cert-key pair'''
    conf_data = {'common_name': cn}
    conf = INOPENSSL_CONF_TEMPLATE.format(**conf_data)
    if SERIAL_NUMBER != '':
        conf_ser_data = {'serial_number': SERIAL_NUMBER}
        conf_ser = INOPENSSL_SERIAL_CONF_TEMPLATE.format(**conf_ser_data)
    with open(INOPENSSL_CONF_FILE, 'w') as f:
        f.write(conf)
        if SERIAL_NUMBER != '':
            f.write(conf_ser)

    cmd = 'openssl genrsa -out ' + KEY_PEM + ' 2048'
    cmd = cmd + ' && openssl req -config ' + INOPENSSL_CONF_FILE + ' -new -key ' + KEY_PEM + ' -out ' + CSR_PEM
    cmd = cmd + ' && openssl dgst -sha256 -hmac ' + phrase + ' -out ' + SIGN + ' ' + CSR_PEM
    print("Now passphrase is {}".format(phrase))
    ret, out = run(cmd)
    if ret != 0:
        return False

    hmac = ''
    certreq = ''
    with open(SIGN) as f:
        hmac = f.read().strip().split(' ')[-1]
    with open(CSR_PEM) as f:
        certreq = f.read().strip()

    if not make_certreq(nodeip, hmac, certreq):
        logger.info('Generation of [crt, key, ca] failed')
        return False

    with open(KEY_PEM, 'r') as f:
        logger.info('Generated key\n [key]\n%s' % f.read().strip())
    shutil.copyfile(KEY_PEM, FINAL_KEY)
    logger.info('Generated pem: [%s, %s, %s] ' % (FINAL_CRT, FINAL_KEY, FINAL_CA))
    if not pair_match(FINAL_CRT, FINAL_KEY, 'pem'):
        return False

    # Cert generation and cert/key match success
    return True


def make_certreq(nodeip, hmac, certreq):
    url = 'https://%s/raca/certreq.json' % nodeip
    payload = '{"aaaCertGenReq":{"attributes":{"type":"%s","hmac":"%s", "certreq": "%s", "podip": "%s", "podmac": "%s", "podname": "%s"}}}' % ("csvc", hmac, certreq, MY_NODE_IDIP, MY_CHASSIS_ID, MY_SN)
    logger.info('Request url : %s' % url)
    logger.info('Request body: %s' % payload)
    response = session.post(url, data=payload, verify=False, timeout=5)
    logger.info('Request res: %s' % response.text)
    if response.status_code != 200:
        logger.error('aaaCertGenReq request failed')
        return False
    logger.info('aaaCertGenReq request succeded')
    json_out = json.loads(response.text.replace('\n', '\\n'))
    rootres = str(json_out['imdata'][0]['aaaApplianceCertRes']['attributes']['rootres']).strip()
    certres = str(json_out['imdata'][0]['aaaApplianceCertRes']['attributes']['certres']).strip()
    blobres = str(json_out['imdata'][0]['aaaApplianceCertRes']['attributes']['blobres']).strip()
    logger.info('Retrieved ca, crt\n [ca]\n%s\n [crt]\n%s\n [blob]\n%s' % (rootres, certres, blobres))
    with open(FINAL_CA, 'w') as f:
        f.write(rootres)
    with open(FINAL_CRT, 'w') as f:
        f.write(certres)
    if blobres:
        with open(FINAL_BLOB, 'w') as f:
            f.write(blobres)
    return True


def make_copies():
    for src, dst in CERT_COPY:
        if os.path.exists(src):
            run('cp %s %s' % (src, dst))


def delete_copies():
    for src, dst in CERT_COPY:
        if os.path.exists(dst):
            run('rm -f %s' % dst)


def convert_certs():
    '''Converts PEM certificates to PKCS8, PKCS12 and DER'''
    cmd = 'openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ' + FINAL_KEY + ' -out ' + FINAL_P8
    ret, out = run(cmd)
    if ret != 0:
        return False
    logger.info('Generated pkcs8: [%s] ' % FINAL_P8)

    cmd = 'openssl pkcs12 -export -inkey ' + FINAL_KEY + ' -in ' + FINAL_CRT + ' -certfile ' + FINAL_CA + ' -out ' + FINAL_P12 + ' -passout pass:' + EXPORT_PASS
    ret, out = run(cmd)
    if ret != 0:
        return False
    logger.info('Generated pkcs12: [%s] ' % FINAL_P12)

    cmd = 'openssl x509 -outform der -in ' + FINAL_CRT + ' -out ' + FINAL_CRT_DER
    cmd = cmd + ' && openssl x509 -outform der -in ' + FINAL_CA + ' -out ' + FINAL_CA_DER
    cmd = cmd + ' && openssl rsa -outform der -in ' + FINAL_KEY + ' -out ' + FINAL_KEY_DER
    ret, out = run(cmd)
    if ret != 0:
        return False
    logger.info('Generated der: [%s, %s, %s] ' % (FINAL_CRT_DER, FINAL_KEY_DER, FINAL_CA_DER))
    if not pair_match(FINAL_CRT_DER, FINAL_KEY_DER, 'der'):
        return False

    # Cert convertions and cert/key match success
    return True


def get_passphrase(nodeip, username, password):
    '''Retrieves passphrase'''
    url = 'https://%s/api/aaaLogin.json' % nodeip
    payload = '{"aaaUser":{"attributes":{"name":"%s","pwd":"%s"}}}' % (username, password)
    logger.info('Request url : %s' % url)
    # do not log password
    logger.info('Request body: %s' % payload.replace(password, '********'))
    response = session.post(url, data=payload, verify=False, timeout=5)
    logger.info('Request res: %s' % response.text)
    if response.status_code != 200:
        logger.error('aaaLogin request failed')
        return False, ''
    logger.info('aaaLogin request succeded')

    url = 'https://%s/api/node/class/pkiFabricSelfCAEp.json' % nodeip
    logger.info('Request url : %s' % url)
    response = session.get(url, verify=False, timeout=5)
    logger.info('Request res: %s' % response.text)
    if response.status_code != 200:
        logger.error('pkiFabricSelfCA request failed')
        return False, ''
    logger.info('pkiFabricSelfCA request succeded')
    json_out = response.json()
    passphrase = str(json_out['imdata'][0]['pkiFabricSelfCAEp']['attributes']['currCertReqPassphrase'])
    logger.info('Retrieved passphrase [%s]' % passphrase)
    return True, passphrase


def pair_match(crt, key, cert_format):
    '''Checks if cert-key match eachother'''
    ret, crt_out = run('openssl x509 -inform ' + cert_format + '  -noout -modulus -in ' + crt + ' | openssl md5')
    ret, key_out = run('openssl rsa -inform ' + cert_format + ' -noout -modulus -in ' + key + ' | openssl md5')
    if crt_out == key_out:
        logger.info('[%s, %s] - Match ' % (crt, key))
        return True
    else:
        logger.error('[%s, %s] - Mismatch' % (crt, key))
        return False


def parse_args():
    # Parse arguments
    parser = argparse.ArgumentParser(description='command help')
    parser.add_argument('--workdir', default='/tmp/', help='Work directory')
    parser.add_argument('--logdir', default='/tmp/', help='Log directory')
    parser.add_argument('--logfile', default='gen_cert.log', help='Log file')
    subparsers = parser.add_subparsers(dest='command', help='sub-command help')
    parser_generate = subparsers.add_parser('generate', help='Generate files')
    parser_generate.add_argument('--sn', default='', required=False, help='Serial Number', nargs='+')
    parser_generate.add_argument('--cn', required=True, help='Common Name', nargs='+')
    parser_generate.add_argument('--nodeip', default='localhost', help='Node Ip')
    parser_generate.add_argument('--passphrase', help='Passphrase')
    parser_generate.add_argument('--username', help='Username')
    parser_generate.add_argument('--password', default='noir0!234', help='Password')
    parser_generate.add_argument('--reqtype', choices=['csvc', 'vtor', 'vapic'], help='Request type', default='csvc')
    parser_generate.add_argument('--mynodeidip', help='My Node Id:Ip')
    parser_generate.add_argument('--mychassisid', help='My Chassis Id')
    parser_generate.add_argument('--mysn', help='My SN')
    args = parser.parse_args()
    return args


def generate(workdir, nodeip, cn, user, password):
    previous_dir = os.getcwd()
    os.chdir(workdir)
    ret, PASSPHRASE = get_passphrase(nodeip, user, password)
    if not ret:
        print("Arguments: Could not fetch passphrase using credentials")
        os.chdir(previous_dir)
        return False
    else:
        print("passphrase: {}".format(PASSPHRASE))

    if generate_pair(nodeip, PASSPHRASE, cn) and convert_certs():
        cleanup(True)
        make_copies()
        os.chdir(previous_dir)
        return True

    os.chdir(previous_dir)
    return False

'''
Generate certificate and key for nexus dashboard

@author:     Gautam Venkataramanan

@copyright:  2021 Cisco Systems. All rights reserved.
@contact:    gautvenk@cisco.com
'''

import subprocess
import logging
import sys
import os
import requests
import json
import shutil
import base64

KEY_PEM = 'temp.key.pem'
CSR_PEM = 'temp.csr.pem'
TMP_PEM = 'temp.pem'
SIGN = 'temp.sign'

FINAL_CRT = 'server.crt'
FINAL_KEY = 'server.key'
FINAL_CA = 'cacert.crt'

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

logger = None

session = requests.Session()
retry = requests.packages.urllib3.util.retry.Retry(total=3, read=3, connect=3, backoff_factor=0.3, status_forcelist=(500, 502, 503))
session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retry))

def set_logger(logdir, logfile):
    '''create logger'''
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
    '''run the given command'''
    shell = True if type(cmd) is str else False
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=shell)
    out = proc.communicate()[0].strip()
    logger.info('>> %s | RETURN: %d' % (cmd, proc.returncode))
    if proc.returncode != 0:
        logger.error(out)
    return proc.returncode, out

def cleanup(keep_final=True):
    '''Cleanup temporary files'''
    tmp_files = [KEY_PEM, CSR_PEM, SIGN, INOPENSSL_CONF_FILE]
    final_files = [FINAL_CRT, FINAL_KEY, FINAL_CA]
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

def sanitize_key(src_file):
    '''Sanitize key according to how ND wants it'''
    lines = []
    with open(src_file) as infile, open(TMP_PEM, 'w') as outfile:
        for line in infile:
            line = line.strip()
            if not line:
                continue
            lines.append(line)
        outfile.write('\\n'.join(lines))
    shutil.move(TMP_PEM, src_file)

def sanitize_csr(src_file):
    '''Sanitize csr file according to how ND wants it'''
    # ND expects csr to be sent in base64 format. hmac needs to be signed
    # with original unencoded csr. ND does 'base64 -decode' of the csr that
    # we send and then generate sign to compare with the hmac that we send.
    # It so happens that there is a secret newline char that gets removed
    # when we 'base64 -d' and that leads to different hmac generation. To
    # avoid this issue, we are encoding and decoding CSR to have same behavior
    # as ND.
    with open(src_file) as infile, open(TMP_PEM, 'w') as outfile:
        csr = infile.read().strip()
        csr_bytes = csr.encode('ascii')
        base64_csr_bytes = base64.b64encode(csr_bytes)
        base64_csr_msg = base64_csr_bytes.decode('ascii')

        base64_csr_bytes = base64.b64decode(base64_csr_bytes)
        csr = base64_csr_bytes.decode('ascii')

        outfile.write(csr)
    shutil.move(TMP_PEM, src_file)
    return base64_csr_msg

def generate_pair(nodeip, jwttoken, passphrase, cn):
    '''Generates a cert-key pair'''
    conf_data = {'common_name': cn}
    conf = INOPENSSL_CONF_TEMPLATE.format(**conf_data)

    with open(INOPENSSL_CONF_FILE, 'w') as f:
        f.write(conf)

    # Generate private key
    cmd = 'openssl genrsa -out ' + KEY_PEM + ' 2048'
    ret, _ = run(cmd)
    if ret != 0:
        return False

    # The CSR is created using the PEM format and contains the public key portion of the private key
    # as well as information about you (or your company).
    cmd = 'openssl req -config ' + INOPENSSL_CONF_FILE + ' -new -key ' + KEY_PEM + ' -out ' + CSR_PEM
    ret, _ = run(cmd)
    if ret != 0:
        return False

    # cert signing request
    csr = sanitize_csr(CSR_PEM)

    # Generate digital signature for CSR
    cmd = 'openssl dgst -sha256 -hmac ' + passphrase + ' -out ' + SIGN + ' ' + CSR_PEM
    ret, _ = run(cmd)
    if ret != 0:
        return False

    # hash-message auth code
    hmac = ''
    with open(SIGN) as f:
        hmac = f.read().strip().split(' ')[-1]

    if not make_certreq(nodeip, hmac, csr):
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

def pair_match(crt, key, cert_format):
    '''Checks if cert-key match eachother'''
    _, crt_out = run('openssl x509 -inform ' + cert_format + '  -noout -modulus -in ' + crt + ' | openssl md5')
    _, key_out = run('openssl rsa -inform ' + cert_format + ' -noout -modulus -in ' + key + ' | openssl md5')
    if crt_out == key_out:
        logger.info('[%s, %s] - Match ' % (crt, key))
        return True
    else:
        logger.error('[%s, %s] - Mismatch' % (crt, key))
        return False

# Note: Currently csr and signature are locally generated so that we dont
# give private key to ND
def get_csr_and_signature_from_nd(nodeip, jwttoken, passphrase, cn):
    '''Generate CSR and signature from ND'''
    # pvt key
    key = ''
    sanitize_key(KEY_PEM)
    with open(KEY_PEM) as f:
        key = f.read().strip()

    url = 'https://%s/api/config/csr/.json' % nodeip
    logger.info('Request url : %s' % url)
    head = {'Authorization': '{}'.format(jwttoken)}
    payload = '{"rsaKey": "%s", "signKey": "%s", "signatureType": "Passphrase", "commonName": "%s"}' % (key, passphrase, cn)
    response = session.post(url, headers=head, data=payload, verify=False, timeout=5)
    logger.info('Request res: %s' % response.text)
    if response.status_code != 200:
        logger.error('csr request failed %s' % response.status_code)
        return False, ''
    logger.info('csr request succeded')

def make_certreq(nodeip, hmac, csr):
    '''Request ND to give ca and certificate'''
    url = 'https://%s/sedgeapi/v1/kms/ca/' % nodeip
    payload = '{"reqData":"%s","signature":"%s", "signatureType": "Passphrase"}' % (csr, hmac)
    logger.info('Request url : %s' % url)
    logger.info('Request body: %s' % payload)
    response = session.post(url, data=payload, verify=False, timeout=5)
    logger.info('Request res: %s' % response.text)
    if response.status_code != 200:
        logger.error('ca request failed')
        return False
    logger.info('ca request succeded')
    json_out = json.loads(response.text.replace('\n', '\\n'))
    ca = str(json_out['response'][1]['ca']).strip()
    certificate = str(json_out['response'][1]['certificate']).strip()
    logger.info('Retrieved ca, crt\n [ca]\n%s\n [crt]\n%s' % (ca, certificate))
    with open(FINAL_CA, 'w') as f:
        f.write(ca)
    with open(FINAL_CRT, 'w') as f:
        f.write(certificate)

    return True

def get_jwttoken(nodeip, username, password):
    '''Retrieves jwttoken'''
    url = 'https://%s/login.json' % nodeip
    payload = '{"userName":"%s","userPasswd":"%s","domain":"DefaultAuth"}' % (username, password)
    logger.info('Request url : %s' % url)
    # do not log password
    logger.info('Request body: %s' % payload.replace(password, '********'))
    response = session.post(url, data=payload, verify=False, timeout=5)
    logger.info('Request res: %s' % response.text)
    if response.status_code != 200:
        logger.error('aaaLogin request failed %s' % response.status_code)
        return False, ''
    logger.info('aaaLogin request succeded')
    json_out = response.json()
    jwttoken = json_out['jwttoken']
    logger.info('Retrieved jwttoken [%s]' % jwttoken)
    return True, jwttoken

def get_passphrase(nodeip, jwttoken):
    '''Retrieves passphrase'''
    url = 'https://%s/api/config/passphrase/.json' % nodeip
    logger.info('Request url : %s' % url)

    head = {'Authorization': '{}'.format(jwttoken)}
    response = session.post(url, headers=head, data="{}", verify=False, timeout=5)
    logger.info('Request res: %s' % response.text)
    if response.status_code != 200:
        logger.error('passphrase request failed %s' % response.status_code)
        return False, ''
    logger.info('passphrase request succeded')
    json_out = response.json()
    passphrase = str(json_out['response'][1]['currCertReqPassphrase'])
    logger.info('Retrieved passphrase [%s]' % passphrase)
    return True, passphrase

def generate(workdir, nodeip, cn, user, password):
    '''Generate key, certificate and ca'''
    previous_dir = os.getcwd()
    os.chdir(workdir)
    ret, jwttoken = get_jwttoken(nodeip, user, password)
    if not ret:
        print("Could not fetch jwttoken using credentials")
        os.chdir(previous_dir)
        return False

    ret, passphrase = get_passphrase(nodeip, jwttoken)
    if not ret:
        print("Could not fetch passphrase using jwttoken")
        os.chdir(previous_dir)
        return False

    if generate_pair(nodeip, jwttoken, passphrase, cn):
        cleanup(True)
        os.chdir(previous_dir)
        return True

    os.chdir(previous_dir)
    return False

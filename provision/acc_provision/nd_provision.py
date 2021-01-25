from __future__ import print_function, unicode_literals

import os
import os.path
import tempfile
if __package__ is None or __package__ == '':
    import nd_kafka_cert
else:
    from . import nd_kafka_cert


class NDProvision(object):
    def __init__(self, config, user_args):
        self.config = config
        self.args = user_args

    def Run(self):
        self.addKafkaConfig()

    def addKafkaConfig(self):
        cKey, cCert, caCert = self.getKafkaCerts(self.config)
        # We want to generate the ND certs always even if ND config
        # isnt present in input file. This is so that the secrets already
        # get created with the appropriate volumeMounts. Whenever ND updates
        # CRD with cert info, the secrets should just be updated with new
        # base64 encoded information.
        if "nd_config" not in self.config:
            self.config["nd_config"] = {}
        self.config["nd_config"]["kafka"] = {}
        self.config["nd_config"]["kafka"]["key"] = cKey.encode()
        self.config["nd_config"]["kafka"]["cert"] = cCert.encode()
        self.config["nd_config"]["kafka"]["cacert"] = caCert.encode()

    def getKafkaCerts(self, config):
        if self.config["provision"]["skip-nd-kafka-certs"]:
            return "none", "none", "none"
        wdir = tempfile.mkdtemp()
        nd_host = self.config["nd_config"]["nd_hosts"][0]
        user = self.config["nd_config"]["nd_login"]["username"]
        pwd = self.config["nd_config"]["nd_login"]["password"]
        cn = self.config["aci_config"]["system_id"]
        nd_kafka_cert.logger = nd_kafka_cert.set_logger(wdir, "nd-kc.log")
        res = nd_kafka_cert.generate(wdir, nd_host, cn, user, pwd)
        if not res:
            raise(Exception("Failed to get kafka certs"))

        readDict = {
            "server.key": "",
            "server.crt": "",
            "cacert.crt": "",
        }

        dir = wdir + "/"
        for fname in readDict:
            f = open(dir + fname, "r")
            readDict[fname] = f.read()
            f.close()

        os.system('rm -rf ' + wdir)
        return readDict["server.key"], readDict["server.crt"], readDict["cacert.crt"]

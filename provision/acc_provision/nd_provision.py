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
        # Note: skip-kafka-certs is used to skip kafka cert generation
        # for both overlay CAPIC and nexus dashboard.
        if self.config["provision"]["skip-kafka-certs"]:
            return "none", "none", "none"
        if "nd_config" not in self.config:
            return "none", "none", "none"
        cKey, cCert, caCert = self.getKafkaCerts(self.config)
        self.config["nd_config"]["kafka"] = {}
        self.config["nd_config"]["kafka"]["key"] = cKey.encode()
        self.config["nd_config"]["kafka"]["cert"] = cCert.encode()
        self.config["nd_config"]["kafka"]["cacert"] = caCert.encode()

    def getKafkaCerts(self, config):
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


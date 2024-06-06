# Script to set serviceBdRoutingDisable attribute of service BD as yes
#
# Run python3 aci_set_service_bd_routing_disable_yes.py --help for usage
#
# eg: python3 aci_set_service_bd_routing_disable_yes.py -c <acc-provision input yaml file>
#     -u <APIC username> -p <APIC password>

from __future__ import print_function, unicode_literals
import collections
import json
import sys
import re
import requests
import urllib3
import ipaddress
import argparse
import copy
import os
import os.path
import yaml
import time
from distutils.version import StrictVersion

debug_http = False

if debug_http:
    import logging
    import http.client as http_client

    http_client.HTTPConnection.debuglevel = 1
    # You must initialize logging, otherwise you'll not see debug output.
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception as e:
    print(f"Error: {e}")

apic_debug = False
apic_cookies = {}
apic_default_timeout = (15, 90)


def err(msg):
    print("ERR:  " + msg, file=sys.stderr)


def warn(msg):
    print("WARN: " + msg, file=sys.stderr)


def dbg(msg):
    if apic_debug:
        print("DBG:  " + msg, file=sys.stderr)


def info(msg):
    print("INFO: " + msg, file=sys.stderr)


def yesno(flag):
    if flag:
        return "yes"
    return "no"


class Apic(object):

    def __init__(
        self,
        addr,
        username,
        password,
        ssl=True,
        verify=False,
        timeout=None,
        debug=False,
    ):
        global apic_debug
        apic_debug = debug
        self.addr = addr
        self.ssl = ssl
        self.username = username
        self.password = password
        self.cookies = apic_cookies.get((addr, username, ssl))
        self.errors = 0
        self.verify = verify
        self.timeout = timeout if timeout else apic_default_timeout
        self.debug = debug

        if self.cookies is None:
            self.login()
            if self.cookies is not None:
                apic_cookies[(addr, username, ssl)] = self.cookies
        self.apic_versions = self.get_apic_versions()

    def url(self, path):
        if self.ssl:
            return "https://%s%s" % (self.addr, path)
        return "http://%s%s" % (self.addr, path)

    def get(self, path, data=None, params=None):
        args = dict(data=data, cookies=self.cookies, verify=self.verify, params=params)
        args.update(timeout=self.timeout)
        dbg("getting path: {} {}".format(path, json.dumps(args)))
        resp = requests.get(self.url(path), **args)
        return resp

    def post(self, path, data):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        args.update(timeout=self.timeout)
        dbg("posting {}".format(json.dumps(args)))
        return requests.post(self.url(path), **args)

    def login(self):
        data = '{"aaaUser":{"attributes":{"name": "%s", "pwd": "%s"}}}' % (
            self.username,
            self.password,
        )
        path = "/api/aaaLogin.json"
        req = requests.post(self.url(path), data=data, verify=False)
        if req.status_code == 200:
            resp = json.loads(req.text)
            dbg("Login resp: {}".format(req.text))
            token = resp["imdata"][0]["aaaLogin"]["attributes"]["token"]
            self.cookies = collections.OrderedDict([("APIC-Cookie", token)])
        else:
            print("Login failed - {}".format(req.text))
            print(
                "Addr: {} u: {} p: {}".format(self.addr, self.username, self.password)
            )
        return req

    def check_resp(self, resp):
        respj = json.loads(resp.text)
        if len(respj["imdata"]) > 0:
            ret = respj["imdata"][0]
            if "error" in ret:
                raise Exception("APIC REST Error: %s" % ret["error"])
        return resp

    def get_path(self, path, multi=False):
        ret = None
        try:
            resp = self.get(path)
            self.check_resp(resp)
            respj = json.loads(resp.text)
            if len(respj["imdata"]) > 0:
                if multi:
                    ret = respj["imdata"]
                else:
                    ret = respj["imdata"][0]
        except Exception as e:
            self.errors += 1
            err("Error in getting %s: %s: " % (path, str(e)))
        return ret

    def process_apic_version_string(self, raw):
        # Given the APIC version for example 5.2(3e), convert it to 5.2.3 for comparison
        split_string = raw.split("(")
        major_version = split_string[0]
        minor_string = split_string[1]
        numeric_filter = filter(str.isdigit, minor_string)
        minor_version = "".join(numeric_filter)
        return major_version + "." + minor_version

    def get_apic_versions(self):
        path = "/api/node/class/firmwareCtrlrRunning.json"
        versions = []
        try:
            multi_data = self.get_path(path, multi=True)
            for data in multi_data:
                dbg("APIC version data: %s" % data)
                versionStr = data["firmwareCtrlrRunning"]["attributes"]["version"]
                versions.append(self.process_apic_version_string(versionStr))
            dbg("APIC versions obtained: {}".format(versions))
        except Exception as e:
            dbg("Unable to get APIC version object %s: %s" % (path, str(e)))
        return versions


def get_apic(config, apic_id=0):
    if config["aci_config"].get("apic_oobm_ip"):
        apic_host = config["aci_config"]["apic_oobm_ip"]
    else:
        apic_host = config["aci_config"]["apic_hosts"][apic_id]
    apic_username = config["aci_config"]["apic_login"]["username"]
    apic_password = config["aci_config"]["apic_login"]["password"]
    timeout = config["aci_config"]["apic_login"]["timeout"]

    if config["aci_config"]["apic_proxy"]:
        apic_host = config["aci_config"]["apic_proxy"]
    apic = Apic(
        apic_host,
        apic_username,
        apic_password,
        timeout=timeout,
        debug=apic_debug,
    )
    if apic.cookies is None:
        return None
    return apic


class CustomFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        ret = super(CustomFormatter, self)._format_action_invocation(action)
        ret = ret.replace(" ,", ",")
        ret = ret.replace(" file,", ",")
        ret = ret.replace(" name,", ",")
        ret = ret.replace(" pass,", ",")
        return ret


def parse_args(show_help):
    parser = argparse.ArgumentParser(
        description="Run script to set serviceBdRoutingDisable yes if APIC version is 6.0(4a) or higher",
        formatter_class=CustomFormatter,
    )
    parser.add_argument(
        "--debug", action="store_true", default=False, help="enable debug"
    )
    parser.add_argument(
        "-c",
        "--config",
        default="-",
        metavar="file",
        help="input file with your fabric configuration",
    )
    parser.add_argument(
        "-u",
        "--username",
        default=None,
        metavar="name",
        help="apic-admin username to use for APIC API access",
    )
    parser.add_argument(
        "-p",
        "--password",
        default=None,
        metavar="pass",
        help="apic-admin password to use for APIC API access",
    )
    parser.add_argument(
        "-w",
        "--timeout",
        default=None,
        metavar="timeout",
        help="wait/timeout to use for APIC API access",
    )
    parser.add_argument(
        "--apic-proxy", default=None, metavar="addr", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--apic-oobm-ip",
        default=None,
        metavar="ip",
        help="APIC out of band management IP for day0 configuration",
    )
    # If the input has no arguments, show help output and exit
    if show_help:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


def config_user(config_file):
    config = {}
    if config_file:
        if config_file == "-":
            info('Loading configuration from "STDIN"')
            data = sys.stdin.read()
            config = yaml.safe_load(data)
        else:
            info('Loading configuration from "%s"' % config_file)
            with open(config_file, "r") as file:
                config = yaml.safe_load(file)

            with open(config_file, "r") as file:
                data = file.read()

        user_input = re.sub("password:.*", "", data)
        config["user_input"] = user_input
    if config is None:
        config = {}
    return config


def deep_merge(user, default):
    if isinstance(user, dict) and isinstance(default, dict):
        for k, v in default.items():
            if k not in user:
                user[k] = v
            else:
                user[k] = deep_merge(user[k], v)
    return copy.deepcopy(user)


def check_service_bd_routing_disable(
    config, apic, service_bd_routing_disable_true_count
):
    path = "/api/node/mo/uni/tn-{}/BD-{}_bd_kubernetes-service.json".format(
        config["aci_config"]["vrf"]["tenant"], config["aci_config"]["system_id"]
    )
    try:
        resp = apic.get(path)
        if resp is None:
            raise Exception("Failed to get fvbd")
        respj = json.loads(resp.text)
        service_bd_routing_disable = respj["imdata"][0]["fvBD"]["attributes"][
            "serviceBdRoutingDisable"
        ]
        if service_bd_routing_disable == "yes":
            service_bd_routing_disable_true_count += 1
            dbg(
                "serviceBdRoutingDisable is set to yes, incrementing count, service_bd_routing_disable_true_count: %s"
                % service_bd_routing_disable_true_count
            )
        else:
            info("serviceBdRoutingDisable is set to no for APIC with IP: {}, setting it to yes".format(apic.addr))
            data = collections.OrderedDict(
                [
                    (
                        "fvBD",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [
                                            (
                                                "dn",
                                                "uni/tn-{}/BD-{}_bd_kubernetes-service".format(
                                                    config["aci_config"]["vrf"][
                                                        "tenant"
                                                    ],
                                                    config["aci_config"]["system_id"],
                                                ),
                                            ),
                                            (
                                                "name",
                                                "{}_bd_kubernetes-service".format(
                                                    config["aci_config"]["system_id"]
                                                ),
                                            ),
                                            ("serviceBdRoutingDisable", "yes"),
                                            ("status", "modified"),
                                        ]
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            )
            data = json.dumps(data, indent=4, separators=(",", ": "))
            resp = apic.post(path, data)
            if resp.status_code != 200:
                raise Exception(
                    "Failed to set serviceBdRoutingDisable to yes, resp: {}".format(
                        resp.text
                    )
                )
            info("serviceBdRoutingDisable set to yes")
        return service_bd_routing_disable_true_count
    except Exception as e:
        err("Error in getting %s: %s: " % (path, str(e)))


def set_service_bd_routing_disable(apic_count, config, service_bd_routing_disable_true_count):
    for apic_id in range(apic_count):
        apic = get_apic(config, apic_id)
        if apic is None:
            raise Exception("Failed to connect to APIC")
        for apic_version in apic.apic_versions:
            if StrictVersion(apic_version) >= StrictVersion("6.0.4"):
                dbg(
                    "APIC IP: {}, APIC Version: {}. Version is 6.0(4a) or higher".format(
                        config["aci_config"]["apic_hosts"][apic_id],
                        apic_version,
                    )
                )
                service_bd_routing_disable_true_count = (
                    check_service_bd_routing_disable(
                        config, apic, service_bd_routing_disable_true_count
                    )
                )
                break
    return service_bd_routing_disable_true_count

# Main function
def main(args=None):
    if args is None:
        args = parse_args(len(sys.argv) == 1)

    if args.apic_oobm_ip and is_valid_ip(args.apic_oobm_ip) is False:
        err("Invalid apic-oobm-ip address: " + args.apic_oobm_ip)
        sys.exit(1)

    global apic_debug
    apic_debug = args.debug

    config_file = args.config
    timeout = None
    if args.timeout:
        try:
            if int(args.timeout) >= 0:
                timeout = int(args.timeout)
        except ValueError:
            # ignore that timeout value
            warn("Invalid timeout value ignored: '%s'" % timeout)

    config = {
        "aci_config": {
            "apic_login": {},
            "apic_proxy": args.apic_proxy,
        },
    }

    if args.apic_oobm_ip:
        config["aci_config"]["apic_oobm_ip"] = args.apic_oobm_ip
    if args.username:
        config["aci_config"]["apic_login"]["username"] = args.username

    config["aci_config"]["apic_login"]["password"] = (
        args.password if args.password else os.environ.get("ACC_PROVISION_PASS")
    )
    config["aci_config"]["apic_login"]["timeout"] = timeout

    user_config = config_user(config_file)
    config["user_config"] = copy.deepcopy(user_config)
    deep_merge(config, user_config)

    apic_count = len(config["aci_config"]["apic_hosts"])
    while True:
        try:
            service_bd_routing_disable_true_count = 0
            service_bd_routing_disable_true_count = set_service_bd_routing_disable(apic_count,
                    config, service_bd_routing_disable_true_count)
            if service_bd_routing_disable_true_count == apic_count:
                info(
                    "All APICs have version 6.0(4a) or higher and serviceBdRoutingDisable set to yes. Exiting the script"
                )
                exit(0)
            time.sleep(10)
        except KeyboardInterrupt:
            exit(0)
        except Exception as e:
            print(f"Error: {e}")
            # If there's an error, wait for 10 seconds before trying again
            time.sleep(10)


if __name__ == "__main__":
    main()

#!/usr/bin/python3
import argparse
from dataclasses import dataclass
import ipaddress
import json
import subprocess
import sys
import re
import time
import os
import signal
import logging
import struct
import multiprocessing
from typing import Dict, List

import daemon
from lockfile import LockFile, LockError, LockTimeout
from flask import Flask, jsonify, request


# Set up logging to file
file_handler = logging.FileHandler(filename="fw_app.log", mode="a", encoding="utf-8")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[file_handler],
)

logger = logging.getLogger(__name__)
app = Flask(__name__)

# Path to the XDP program
XDP_PROGRAM = "xdp_firewall.o"

# Names of the BPF maps
# BPF_MAP_NAMES = ["rules_map", "action_data_map"]
BPF_MAP_NAMES = ["rules_map"]

# Name of the BPF map that stores the firewall rules
BPF_MAP_RULES = "rules_map"


@dataclass
class Rule:
    action: int  # 0 = DROP, 1 = ACCEPT, 2 = RATE_LIMIT
    ip_src: str  # IP address in string format
    ip_src_mask: int  # IP address mask length
    ip_dst: str  # IP address in string format
    ip_dst_mask: int  # IP address mask length
    ip_proto: int  # IP protocol number, e.g., 6 for TCP, 17 for UDP, 1 for ICMP
    l4_sport: int  # L4 source port
    l4_dport: int  # L4 destination port
    rate_limit: int  # Rate limit in packets per second (only used if action is RATE_LIMIT)


class Firewall:
    def __init__(self, if_names: List[str]):
        self.if_names: List[str] = if_names
        # Construct a byte string key for the BPF map. The key is a __u32 that is the index of the rule in the BPF map.
        self.rule_key_format = "I"  # I denotes a 32-bit unsigned integer

        # Validate the size of the rule key struct
        key_size = struct.calcsize(self.rule_key_format)
        if key_size != 4:
            logger.error(f"Invalid rule key size {key_size}. Expected 4 bytes.")
            sys.exit(1)

        # Construct a byte string value for the BPF map. The value is a concatenation of the rule's action and action data.
        # The struct format to match is:
        # struct rule_data
        # {
        #     __u32 src_ip;   // Source IP address       <<-- already a byte string
        #     __u32 dst_ip;   // Destination IP address  <<-- already a byte string
        #     __u8 protocol;  // IP Protocol (e.g., TCP is 6, UDP is 17, ICMP is 1)
        #     __u16 src_port; // Source port for TCP/UDP
        #     __u16 dst_port; // Destination port for TCP/UDP
        #     __u8 action;    // Action to take (ACCEPT, DROP, or RATE_LIMIT)
        #     __u32 action_data;
        # };
        # Note: = denotes native byte order without alignment padding
        self.rule_data_format = "=4s4sBHHBI"  # I is a 32-bit unsigned integer, B is a 8-bit unsigned integer, H is a 16-bit unsigned integer

        # Validate the size of the rule data struct
        value_size = struct.calcsize(self.rule_data_format)
        if value_size != 18:
            logger.error(f"Invalid rule data size {value_size}. Expected 18 bytes.")
            sys.exit(1)

    def get_if_names(self):
        return self.if_names

    def get_rules(self):
        return self.get_rules_from_map()

    def set_rules_from_json(self, rules_json: List[Dict]):
        rules = self.parse_rules(rules_json)
        for rule_idx, rule in enumerate(rules):
            self.add_rule_to_map(rule_idx, rule)

    def get_rules_from_map(self):
        rules_dict = {}
        rules_from_map = self.dump_map(BPF_MAP_RULES)

        # rules_from_map has a list of dictionaries. Each dictionary has the following keys:
        # key: list of bytes in hex format (e.g., ["0x01", "0x00", "0x00", "0x00"])
        # value: list of bytes in hex format (e.g., ["0x01", "0x00", "0x00", "0x00"])
        for rule_dict in rules_from_map:
            # Convert the key and value to byte strings
            key_bytes = bytes(
                bytearray(int(hex_byte_str, 16) for hex_byte_str in rule_dict["key"])
            )
            logger.info(f"key_bytes: {key_bytes}")
            value_bytes = bytes(
                bytearray(int(hex_byte_str, 16) for hex_byte_str in rule_dict["value"])
            )
            logger.info(f"value_bytes: {value_bytes}")

            # Unpack the key and value byte strings into the rule fields
            (rule_idx,) = struct.unpack(self.rule_key_format, key_bytes)
            (
                ip_src,
                ip_dst,
                ip_proto,
                l4_sport,
                l4_dport,
                action,
                rate_limit,
            ) = struct.unpack(self.rule_data_format, value_bytes)

            # Convert the IP addresses from byte strings to IP addresses
            ip_src = str(ipaddress.IPv4Address(ip_src))
            ip_dst = str(ipaddress.IPv4Address(ip_dst))

            # Convert the rule fields to a Rule object
            rule = Rule(
                action,
                ip_src,
                32,
                ip_dst,
                32,
                ip_proto,
                l4_sport,
                l4_dport,
                rate_limit,
            )

            rules_dict[rule_idx] = rule

        # Sort the rules by index and return them as a list
        return [rules_dict[rule_idx] for rule_idx in sorted(rules_dict.keys())]

    def add_rule_to_map(self, rule_idx, rule: Rule):
        # Add the rule to the BPF map
        logger.info("Adding rule to BPF map")
        logger.debug(str(rule))

        # Construct a byte string key for the BPF map. The key is a __u32 that is the index of the rule in the BPF map.
        rule_key_bytes = struct.pack(self.rule_key_format, rule_idx)
        logger.debug("rule_key_bytes: " + str(rule_key_bytes))

        # Pack the fields into a byte string
        rule_data_bytes = struct.pack(
            self.rule_data_format,
            ipaddress.IPv4Address(rule.ip_src).packed,  # convert to bytes, 4 bytes
            ipaddress.IPv4Address(rule.ip_dst).packed,  # convert to bytes, 4 bytes
            rule.ip_proto,  # 1 byte
            rule.l4_sport,  # 2 bytes
            rule.l4_dport,  # 2 bytes
            rule.action,  # 1 byte
            rule.rate_limit,  # 4 bytes
        )
        logger.debug("rule_data_bytes: " + str(rule_data_bytes))

        # Add the rule to the BPF map
        for if_name in self.if_names:
            # Check if the firewall is enabled on the interface
            if self.get_firewall_if_status(if_name)["status"] == "enabled":
                # Add the rule to the BPF map
                self.update_map(
                    if_name,
                    BPF_MAP_RULES,
                    "add",
                    rule_key_bytes,
                    rule_data_bytes,
                )

    @staticmethod
    def update_map(if_name, map_name, cmd, key, value=""):
        # Add or delete a key/value to/from the BPF map

        # Convert key and value to hex format. Hex needs to be in groups of 2 digits (e.g., 00 00 00 01)
        key_hex_str = key.hex(" ")
        value_hex_str = value.hex(" ")

        if cmd == "add":
            cmd = "sudo bpftool map update pinned /sys/fs/bpf/{}/{} key hex {} value hex {}".format(
                if_name,
                map_name,
                key_hex_str,
                value_hex_str,
            )
            logger.debug("Executing " + cmd)
            output = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if output.returncode != 0:
                logger.debug(output.stdout.decode("utf-8"))
                logger.debug(output.stderr.decode("utf-8"))
                raise Exception(
                    "Failed to add key={} value={} to map {}".format(
                        key_hex_str, value_hex_str, map_name
                    )
                )

        elif cmd == "del":
            cmd = "sudo bpftool map delete pinned /sys/fs/bpf/{}/{} key hex {}".format(
                if_name,
                map_name,
                key_hex_str,
            )
            logger.debug("Executing " + cmd)
            output = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if output.returncode != 0:
                logger.debug(output.stdout.decode("utf-8"))
                logger.debug(output.stderr.decode("utf-8"))
                raise Exception(
                    "Failed to delete key={} from map {}".format(key_hex_str, map_name)
                )

    @staticmethod
    def dump_map(map_name, if_name=None):
        # Dump the contents of the BPF map in json format
        if if_name is None:
            cmd = "sudo bpftool map dump name {} --json".format(map_name)
        else:
            cmd = "sudo bpftool map dump pinned /sys/fs/bpf/{}/{} --json".format(
                if_name, map_name
            )
        logger.debug("Executing " + cmd)
        output = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if output.returncode != 0:
            logger.debug(output.stdout.decode("utf-8"))
            logger.debug(output.stderr.decode("utf-8"))
            raise Exception("Failed to dump map {}".format(map_name))

        return json.loads(output.stdout.decode("utf-8"))

    def get_firewall_if_status(self, if_name: str):
        # Check if the firewall is enabled on the interface
        cmd = "sudo bpftool net show dev {} --json".format(if_name)
        logger.debug("Executing " + cmd)
        output = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if output.returncode != 0:
            logger.debug(output.stdout.decode("utf-8"))
            logger.error(output.stderr.decode("utf-8"))
            return {"status": "error", "message": output.stderr.decode("utf-8")}

        # Check if the firewall is attached to the interface by parsing json output of the command
        # e.g., [{"xdp":[{"devname":"ens33","ifindex":2,"mode":"generic","id":50}],"tc":[],"flow_dissector":[]}]
        try:
            json_output = json.loads(output.stdout.decode("utf-8"))
            for if_dict in json_output[0]["xdp"]:
                if if_dict["devname"] == if_name:
                    return {"status": "enabled"}
            return {"status": "disabled"}
        except Exception as e:
            logger.error(e)
            return {"status": "error", "message": str(e)}

    @staticmethod
    def enable_firewall_if(if_name: str, program):
        try:
            # Load the XDP program, initialize the BPF MAP and attach the program to the interface

            # Create the directory for the interface in the BPF filesystem
            cmd = "sudo mkdir -p /sys/fs/bpf/{}".format(if_name)
            logger.debug("Executing " + cmd)
            output = subprocess.run(
                cmd,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Load the XDP program. The eBPF bytecode is verified by the kernel's verifier for safety and correctness.
            # After the program is successfully loaded, it gets assigned an ID, and it's stored in the kernel.
            # Additionally, this command pins the loaded eBPF program to a specified path in the BPF filesystem
            # (e.g., /sys/fs/bpf/INTERFACE_NAME/xdp_firewall), making it accessible for other tools or scripts to interact with it.
            cmd = "sudo bpftool prog load {} /sys/fs/bpf/{}/prog type xdp".format(
                program, if_name
            )
            logger.debug("Executing " + cmd)
            output = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if output.returncode != 0:
                logger.debug(output.stdout.decode("utf-8"))
                logger.debug(output.stderr.decode("utf-8"))
                raise Exception("Failed to load XDP program")

            # Attach the XDP program to the interface using bpftool.
            # Attach the XDP program to the interface.
            cmd = (
                "sudo bpftool net attach xdp pinned /sys/fs/bpf/{}/prog dev {}".format(
                    if_name, if_name
                )
            )
            logger.debug("Executing " + cmd)
            output = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if output.returncode != 0:
                logger.debug(output.stdout.decode("utf-8"))
                logger.debug(output.stderr.decode("utf-8"))
                raise Exception("Failed to attach XDP program")

            # Pin the BPF maps. Each map is pinned to the BPF filesystem (e.g., /sys/fs/bpf/INTERFACE_NAME/blocked_ips).
            for bpf_map_name in BPF_MAP_NAMES:
                cmd = "sudo bpftool map pin name {} /sys/fs/bpf/{}/{}".format(
                    bpf_map_name, if_name, bpf_map_name
                )
                logger.debug("Executing " + cmd)
                output = subprocess.run(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                if output.returncode != 0:
                    logger.debug(output.stdout.decode("utf-8"))
                    logger.debug(output.stderr.decode("utf-8"))
                    raise Exception("Failed to pin BPF map " + bpf_map_name)

            return True
        except Exception as e:
            logger.error("Failed to enable firewall on interface " + if_name)
            logger.error(e)
            return False

    @staticmethod
    def disable_firewall_if(if_name):
        try:
            # Remove the XDP program from the interface
            output = subprocess.run(
                ["ip", "link", "set", "dev", if_name, "xdp", "off"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if output.returncode != 0:
                logger.debug(output.stdout.decode("utf-8"))
                logger.debug(output.stderr.decode("utf-8"))
                raise Exception("Failed to disable XDP program")

            # Remove the pinned XDP program from the BPF filesystem
            cmd = "sudo rm /sys/fs/bpf/{}/prog".format(if_name)
            logger.debug("Executing " + cmd)
            output = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if output.returncode != 0:
                logger.debug(output.stdout.decode("utf-8"))
                logger.debug(output.stderr.decode("utf-8"))
                raise Exception("Failed to remove XDP program")

            # Remove the pinned BPF maps from the BPF filesystem
            for bpf_map_name in BPF_MAP_NAMES:
                cmd = "sudo rm /sys/fs/bpf/{}/{}".format(if_name, bpf_map_name)
                logger.debug("Executing " + cmd)
                output = subprocess.run(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                if output.returncode != 0:
                    logger.debug(output.stdout.decode("utf-8"))
                    logger.debug(output.stderr.decode("utf-8"))
                    raise Exception("Failed to remove BPF map " + bpf_map_name)

            # Remove the directory for the interface from the BPF filesystem
            cmd = "sudo rmdir /sys/fs/bpf/{}".format(if_name)
            logger.debug("Executing " + cmd)
            output = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if output.returncode != 0:
                logger.debug(output.stdout.decode("utf-8"))
                logger.debug(output.stderr.decode("utf-8"))
                raise Exception("Failed to remove BPF directory")

            return True
        except Exception as e:
            logger.error("Failed to disable firewall on interface " + if_name)
            logger.error(e)
            return False

    @staticmethod
    def parse_rules(rules_json: str) -> List[Rule]:
        rules = []
        for rule in rules_json:
            rules.append(
                Rule(
                    action=int(rule["action"]),
                    ip_src=rule["ip_src"],
                    ip_src_mask=int(rule["ip_src_mask"]),
                    ip_dst=rule["ip_dst"],
                    ip_dst_mask=int(rule["ip_dst_mask"]),
                    ip_proto=int(rule["ip_proto"]),
                    l4_sport=int(rule["l4_sport"]),
                    l4_dport=int(rule["l4_dport"]),
                    rate_limit=int(rule["rate_limit"]),
                )
            )
        return rules


# Status
@app.route("/status", methods=["GET"])
def status():
    logger.info("Received status request")
    # Return OK if the process is running
    return jsonify({"message": "The firewall service is running."})


# Stop
@app.route("/stop", methods=["POST"])
def stop():
    logger.info("Received stop request")
    os.kill(os.getpid(), signal.SIGTERM)
    return jsonify({"message": "The firewall service is stopping."})


# List interfaces
@app.route("/interfaces", methods=["GET"])
def list_interfaces():
    logger.info("Received list interfaces request")
    if_names = fw.get_if_names()
    return jsonify({"interfaces": if_names})


# Enable firewall on an interface
@app.route("/interfaces/<if_name>/enable", methods=["POST"])
def enable_firewall(if_name):
    logger.info("Received enable firewall request for interface {}".format(if_name))
    if not fw.enable_firewall_if(if_name, XDP_PROGRAM):
        return (
            jsonify(
                {
                    "message": "The firewall could not be enabled on interface {}".format(
                        if_name
                    )
                }
            ),
            400,
        )
    return jsonify(
        {"message": "The firewall has been enabled on interface {}".format(if_name)}
    )


# Disable firewall on an interface
@app.route("/interfaces/<if_name>/disable", methods=["POST"])
def disable_firewall(if_name):
    logger.info("Received disable firewall request for interface {}".format(if_name))
    if not fw.disable_firewall_if(if_name):
        return (
            jsonify(
                {
                    "message": "The firewall could not be disabled on interface {}".format(
                        if_name
                    )
                }
            ),
            400,
        )
    return jsonify(
        {"message": "The firewall has been disabled on interface {}".format(if_name)}
    )


# Get status of firewall on an interface
@app.route("/interfaces/<if_name>/status", methods=["GET"])
def get_firewall_status(if_name):
    logger.info("Received get firewall status request for interface {}".format(if_name))
    status = fw.get_firewall_if_status(if_name)
    return jsonify(status)


# Set rules
@app.route("/rules", methods=["POST"])
def set_rules():
    logger.info("Received set rules request")
    rules_json: List[Dict] = request.get_json()["rules"]
    logger.debug("Rules: {}".format(rules_json))
    fw.set_rules_from_json(rules_json)
    return jsonify({"message": "The firewall rules have been updated."})


# Get rules
@app.route("/rules", methods=["GET"])
def list_rules():
    logger.info("Received list rules request")
    rules = fw.get_rules()
    return jsonify({"rules": rules})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Firewall Service")
    parser.add_argument("fw_service_ip", help="The IP address of the firewall service")
    parser.add_argument(
        "if_names", help="The name of the interfaces to attach the firewall", nargs="+"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    if_names: List[str] = args.if_names
    logger.info("Starting firewall service on {}".format(args.fw_service_ip))
    logger.debug("Interfaces: {}".format(if_names))

    # Try acquiring the lock file
    try:
        logger.debug("Acquiring lock file /tmp/fw_app.pid")
        lock = LockFile("/tmp/fw_app.pid")
        lock.acquire(timeout=0)
    except (LockError, LockTimeout):
        logger.error("The firewall service is already running.")
        sys.exit(1)

    # Start the firewall service in a daemon process with PID file to ensure only one instance is running
    # Preserve the opened file descriptors
    with daemon.DaemonContext(
        pidfile=lock,
        files_preserve=[file_handler.stream.fileno()],
        working_directory=os.getcwd(),
    ):
        logger.info("Daemon started")
        fw = Firewall(if_names)
        app.run(
            host=args.fw_service_ip,
            port=5000,
        )

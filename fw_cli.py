#!/usr/bin/python3
# This is a cli tool for managing the firewall service.
# It can be used to start/stop the service, enable/disable the firewall,
# add/remove and list firewall rules.
# The firewall service runs as a separate process.
# The cli tool communicates with it via Rest API.

import argparse
from dataclasses import dataclass
import ipaddress
import json
import os
import signal
import subprocess
import multiprocessing
import sys
import re
import time
import logging
from typing import Dict, List

import requests


# Setups logging to file
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
    datefmt="%d-%m-%Y %H:%M:%S",
    filename="fw_cli.log",
    filemode="a",
)
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Firewall CLI tool")
    parser.add_argument(
        "--fw_service_app",
        default="fw_app.py",
        help="Name of the firewall service app (default: fw_app.py)",
    )
    parser.add_argument(
        "--fw_service_ip",
        default="127.0.0.1",
        help="IP address of the Firewall service (default: 127.0.0.1)",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Start Firewall service
    start_parser = subparsers.add_parser("start", help="Start Firewall service")
    start_parser.add_argument(
        "if_names", help="The name of the interfaces to attach the firewall", nargs="+"
    )

    # Stop Firewall service
    stop_parser = subparsers.add_parser("stop", help="Stop Firewall service")

    # Kill Firewall service
    kill_parser = subparsers.add_parser("kill", help="Kill Firewall service")

    return parser.parse_args()


if __name__ == "__main__":
    # Configure a stream handler to log to stderr
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setLevel(logging.INFO)
    logger.addHandler(stream_handler)

    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        stream_handler.setLevel(logging.DEBUG)

    if args.command == "start":
        # Start Firewall service
        logger.info("Starting Firewall service")
        logger.info("IP address: {}".format(args.fw_service_ip))

        # Start the firewall service with sudo and redirect stdout and stderr to a file fw_app.log
        cmd = "sudo python3 {} {} {} {} >> fw_app.log 2>&1".format(
            args.fw_service_app,
            "--debug" if args.debug else "",
            args.fw_service_ip,
            " ".join(args.if_names),
        )
        logger.debug("Command: {}".format(cmd))

        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            logger.error("Error starting Firewall service: {}".format(e))
            sys.exit(1)

        # Wait for the firewall service to start
        while True:
            logger.info("Waiting for Firewall service to start")
            try:
                resp = requests.get(
                    "http://{}:5000/status".format(args.fw_service_ip), timeout=1
                )
                logger.debug("Response: {}".format(resp.text))
                resp.raise_for_status()
                break
            except requests.exceptions.ConnectionError:
                time.sleep(1)
        logger.info("Firewall service started!")

    elif args.command == "stop":
        # Stop Firewall service
        logger.info("Stopping Firewall service")

        # Send a request to the firewall service to stop
        resp = requests.post(
            "http://{}:5000/stop".format(args.fw_service_ip), timeout=1
        )
        resp.raise_for_status()

        # Wait for the firewall service to stop
        while True:
            logger.info("Waiting for Firewall service to stop")
            try:
                resp = requests.get(
                    "http://{}:5000/status".format(args.fw_service_ip), timeout=1
                )
                resp.raise_for_status()
                time.sleep(1)
            except requests.exceptions.ConnectionError:
                break
        print("Firewall service stopped!")

    elif args.command == "kill":
        # Kill Firewall service
        logger.info("Killing Firewall service")
        # Find the firewall service process and kill it
        firewall_service_pids = [
            int(pid)
            for pid in subprocess.check_output(
                ["pgrep", "-f", args.fw_service_app]
            ).splitlines()
        ]
        logger.debug("Firewall service PIDs: {}".format(firewall_service_pids))
        for firewall_service_pid in firewall_service_pids:
            logger.debug("Killing PID: {}".format(firewall_service_pid))
            # Use sudo to kill the process with the specified PID
            cmd = ["sudo", "kill", str(firewall_service_pid)]
            subprocess.run(cmd, check=True)
        print("Firewall service killed!")

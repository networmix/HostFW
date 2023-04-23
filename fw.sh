#!/bin/bash

set -e

BPF_PROG="xdp_firewall"

USAGE="Usage: $0 COMMAND\n"
USAGE+="    COMMAND is what you expect script to do:\n"
USAGE+="        build - Compile eBPF program.\n"
USAGE+="        setup - Install all dependencies.\n"

if [[ $# -lt 1 ]]; then
    echo>&2 "ERROR: Must specify the command"
    printf "$USAGE" >&2
    exit 2
fi

function build {
    clang -O2 -g -Wall -target bpf -c $BPF_PROG.c -o $BPF_PROG.o
    echo "Compiled successfully!"
    return 0
}

function setup {
    sudo apt-get update
    sudo apt-get install -y build-essential llvm clang libelf-dev libbpf-dev git pkg-config bison flex libfl-dev libpcap-dev linux-tools-common linux-tools-generic gcc-multilib python3-pip
    sudo pip3 install python-daemon flask gunicorn
    echo "Setup complete successfully!"
}

case $1 in
    build)
        echo "Executing BUILD command..."
        build "$@"
        ;;

    setup)
        echo "Executing SETUP command..."
        setup "$@"
        ;;

    *)
      echo>&2 "ERROR: Unknown command $1"
        printf "$USAGE" >&2
        exit 2
        ;;
esac
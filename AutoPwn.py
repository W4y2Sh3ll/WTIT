#!/usr/bin/env python3
import argparse
import logging
import os
from pwncli import *

from analysis import inputDetector
from analysis import protectionDetector
from analysis import backdoorDetector
from analysis import overflowDetector_static
from analysis import overflowDetector_dynamic
from exploits import ret2backdoor

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
    input_funcs = inputDetector.getInputFuncs(binary_file_path)
    properties = protectionDetector.getProperties(binary_file_path)
    backdoors = backdoorDetector.getBackdoors(binary_file_path)
    # overflow_list = overflowDetector_static.analysis(binary_file_path,
    #                                                  input_funcs)
    # if overflow_list is not None:
    #     log.info("[+] Overflow exist")
    #     if backdoors is not None:
    #         payload = ret2backdoor.exploit(binary_file_path, overflow_list,
    #                                        backdoors)
    #         for p in range(len(payload)):
    #             with open('exp_%s' % p, 'wb') as f:
    #                 f.write(payload[p])
    exploitable_state = overflowDetector_dynamic.analysis(binary_file_path)
    ret2backdoor.exploit_dynamic(exploitable_state,backdoors)
    import IPython
    IPython.embed()
    
    



if __name__ == "__main__":
    main()

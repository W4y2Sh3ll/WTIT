from pwn import *


def getProperties(binary_name):

    properties = {}
    binary = ELF(binary_name)
    properties["aslr"] = binary.aslr
    properties["arch"] = binary.arch
    properties["canary"] = binary.canary
    properties["got"] = binary.got
    properties["nx"] = binary.nx
    properties["pie"] = binary.pie
    properties["plt"] = binary.plt
    properties["relro"] = binary.relro
    if "Has RWX segments" in binary.checksec():
        properties['RWX'] = True

    return properties

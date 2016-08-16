#!/usr/bin/python3

import sys, getopt
import time
from os import listdir
from os.path import isfile, isdir, join
from enum import Enum
from Crypto import Random
from Crypto.Cipher import AES


###########################
# Encryption & decryption #
###########################

class Mode(Enum):
    UNDEFINED = 0
    ENCRYPT = 1
    DECRYPT = 2

def _pad(s):
    return s + b'\0' * (AES.block_size - len(s) % AES.block_size)

def _encrypt(message, key):
    message = _pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def _decrypt(message, key):
    iv = message[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(message[AES.block_size:])
    return data.rstrip(b'\0')

def encrypt_file(file, key):
    with open(file, 'rb') as i:
        data = i.read()
    print("Encrypting " + file + " ...")
    e = _encrypt(data, key)
    with open(file, 'wb') as o:
        o.write(e)

def encrypt_dir(dir, key):
    for i in listdir(dir):
        v = join(dir, i)
        if isfile(v):
            encrypt_file(v, key)
        elif isdir(v):
            encrypt_dir(v, key)

def decrypt_file(file, key):
    with open(file, 'rb') as i:
        data = i.read()
    print("Decrypting " + file + " ...")
    d = _decrypt(data, key)
    with open(file, 'wb') as o:
        o.write(d)

def decrypt_dir(dir, key):
    for i in listdir(dir):
        v = join(dir, i)
        if isfile(v):
            decrypt_file(v, key)
        elif isdir(v):
            decrypt_dir(v, key)


###########################
#           Key           #
###########################

# AES-256 key
def _generate_random_key(file):
    key = Random.new().read(32)
    print("Saving key to " + file + " ...")
    try:
        with open(file, 'wb') as o:
            o.write(key)
    except IOError as e:
        print(e)
        return None
    return key

def _get_key(file):
    key = None
    with open(file, 'rb') as i:
        key = i.read(32)
    return key if len(key) == 32 else None


###########################
#           Main          #
###########################

def _usage():
    print("\n  Usage: " + sys.argv[0] + " <options> <files or directories>\n")
    print("  Options:\n"
          "\t-k, --key    <file> : file which contains the 256 bits secret key\n"
          "\t-o, --out    <file> : if no key file is specified for encryption\n"
          "\t                      a 256 bits key will be auto-generated\n"
          "\t                      and written in this new file\n"
          "\t-e, --encrypt       : encrypt files\n"
          "\t-d, --decrypt       : decrypt files\n")

def _exit(code):
    _usage()
    sys.exit(code)

def _run(files, mode, key):
    for i in files:
        if isfile(i):
            if mode == Mode.ENCRYPT:
                encrypt_file(i, key)
            elif mode == Mode.DECRYPT:
                decrypt_file(i, key)
        elif isdir(i):
            if mode == Mode.ENCRYPT:
                encrypt_dir(i, key)
            elif mode == Mode.DECRYPT:
                decrypt_dir(i, key)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hk:o:ed")
    except getopt.GetoptError:
        _exit(2)

    key = gen = None
    mode = Mode.UNDEFINED
    files = []

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            _exit(2)
        elif opt in ("-k", "--key"):
            if gen is not None:
                _exit(2)
            key = _get_key(arg)
        elif opt in ("-o", "--out"):
            if key is not None:
                _exit(2)
            gen = arg
        elif opt in ("-e", "--encrypt"):
            if mode != Mode.UNDEFINED:
                _exit(2)
            mode = Mode.ENCRYPT
        elif opt in ("-d", "--decrypt"):
            if mode != Mode.UNDEFINED:
                _exit(2)
            mode = Mode.DECRYPT

    for arg in args:
        files.append(arg)

    if mode == Mode.ENCRYPT and key is None and gen is not None:
        key = _generate_random_key(gen)

    if len(files) < 1 or mode == Mode.UNDEFINED or key is None:
        _exit(2)

    _run(files, mode, key)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        _exit(2)
    else:
        main(sys.argv[1:])

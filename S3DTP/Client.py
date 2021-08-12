# Networking
import socket

# Compression
import blosc

# Encryption/Hash
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import Salsa20
from Crypto import Random
import random

# Concurrency/Async
import threading

# Memory Management
import psutil as ps

# Timing
import time

# Math
import math

# OS Stuff
import os

# Tracing
import logging

logging.basicConfig(filename='Client.log', filemode="a", encoding='utf-8', level=logging.info, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %H:%M:%S')

class Client:
    def __init__(self, iph, user="", password=""):
        self._user = user
        self._password = password
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._key = Random.urandom(32)
        self._nonce = os.urandom(32)
        random.seed(self._nonce)
        self._sock.connect((iph, 5500))
        data = self._sock.recv(1)
        while (data == b''):
            time.sleep(0.008)
            data = self._sock.recv(1)
        self._sock.send(b'0')
        self._is_encrypted = False
        if (data == b'1'):
            self._is_encrypted = True
            data = self._sock.recv(294)
            while (len(data) < 294):
                time.sleep(0.008)
                data += self._sock.recv(294)
            public = PKCS1_OAEP.new(RSA.importKey(data))
            encrptedKey = public.encrypt(self._key + self._nonce)
            self._sock.sendall(encrptedKey)
            data = self._sock.recv(1)
            while (data == b''):
                time.sleep(0.008)
                data = self._sock.recv(1)
        send = bytes(self._user, "utf-8") + b"\xFF" + bytes(self._user, "utf-8")
        if self._is_encrypted:
            send = Salsa20.new(self._key, random.randbytes(8)).encrypt(send)
        self._sock.send(send)
        data = self._sock.recv(1)
        while data == b'':
            time.sleep(0.008)
            data = self._sock.recv(1)
        if data != b'0':
            print("Auth failed with code " + str(data))

    def __call__(self, iph, user="", password=""):
        try:
            self._sock.close()
        except:
            pass
        self._key = Random.urandom(32)
        self._nonce = os.urandom(32)
        random.seed(self._nonce)
        self._sock.connect((iph, 5500))
        data = self._sock.recv(1)
        while (data == b''):
            time.sleep(0.008)
            data = self._sock.recv(1)
        self._sock.send(b'0')
        self._is_encrypted = False
        if (data == b'1'):
            self._is_encrypted = True
            data = self._sock.recv(294)
            while (len(data) < 294):
                time.sleep(0.008)
                data += self._sock.recv(294)
            public = PKCS1_OAEP.new(RSA.importKey(data))
            encrptedKey = public.encrypt(self._key + self._nonce)
            self._sock.sendall(encrptedKey)
            data = self._sock.recv(1)
            while (data == b''):
                time.sleep(0.008)
                data = self._sock.recv(1)
        send = bytes(self._user, "utf-8") + b"\xFF" + bytes(self._user, "utf-8")
        if self._is_encrypted:
            send = Salsa20.new(self._key, random.randbytes(8)).encrypt(send)
        self._sock.send(send)
        data = self._sock.recv(1)
        while data == b'':
            time.sleep(0.008)
            data = self._sock.recv(1)
        if data != b'0':
            print("Auth failed with code " + str(data))

    # Reads data from file and sends it to the server
    def write_from_file(self, filepath, mode=0, name=""):
        if (name == ""):
            name = filepath
        size = bytes(str(os.stat(filepath).st_size), "utf8")
        if (self._is_encrypted):
            self._sock.send(Salsa20.new(self._key, random.randbytes(8)).encrypt(b'1' + bytes(str(mode), "utf8") + bytes(name, "utf8") + b'\xFF' + size + (b'\xFF' * (253 - len(name) - len(size)))))
        else:
            self._sock.send(b'1' + bytes(str(mode), "utf8") + bytes(name, "utf8") + b'\xFF' + size + (b'\xFF' * (253 - len(name) - len(size))))
        response = self._sock.recv(1)
        while (response == b''):
            time.sleep(0.001)
            response = self._sock.recv(1)
        if (response != b'0'):
            logging.info(response)
            return False
        file = open(filepath, "rb")
        if (mode == 0):
            for i in range(math.ceil((int(size)) / 1000000000) - 1):
                data = blosc.compress(file.read(1000000000), cname="blosclz")
                if (self._is_encrypted):
                    data = Salsa20.new(self._key, random.randbytes(8)).encrypt(data)
                self._sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
                while (self._sock.recv(1) == b''):
                    time.sleep(0.001)
            data = blosc.compress(file.read(1000000000), cname="blosclz")
            if (self._is_encrypted):
                data = Salsa20.new(self._key, random.randbytes(8)).encrypt(data)
            self._sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
            while (self._sock.recv(1) == b''):
                time.sleep(0.001)
            return True
        data = blosc.compress(file.read(), cname="blosclz")
        if (self._is_encrypted):
            data = Salsa20.new(self._key, random.randbytes(8)).encrypt(data)
        self._sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
        while (self._sock.recv(1) == b''):
            time.sleep(0.001)
        return True

    # Reads data from buffer and sends it to the server
    def write_from_memory(self, data, name, mode=0):
        size = bytes(str(len(data)), "utf8")
        if (self._is_encrypted):
            self._sock.send(Salsa20.new(self._key, random.randbytes(8)).encrypt(b'1' + bytes(str(mode), "utf8") + bytes(name, "utf8") + b'\xFF' + size +  (b'\xFF' * (253 - len(name) - len(size)))))
        else:
            self._sock.send(b'1' + bytes(str(mode), "utf8") + bytes(name, "utf8") + b'\xFF' + size +  (b'\xFF' * (253 - len(name) - len(size))))
        response = self._sock.recv(1)
        while (response == b''):
            time.sleep(0.001)
            response = self._sock.recv(1)
        if (response != b'0'):
            logging.info(response)
            return False
        data = blosc.compress(data, cname="blosclz")
        if (self._is_encrypted):
            data = Salsa20.new(self._key, random.randbytes(8)).encrypt(data)
        self._sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
        while (self._sock.recv(1) == b''):
            time.sleep(0.001)
        return True

    # Reads from server
    def read(self, name, filename=""):
        if (self._is_encrypted):
            self._sock.send(Salsa20.new(self._key, random.randbytes(8)).encrypt(b'00' + bytes(name, "utf8") + (b'\xFF' * (254 - len(name)))))
        else:
            self._sock.send(b'00' + bytes(name, "utf8") + (b'\xFF' * (254 - len(name))))
        response = self._sock.recv(2)
        while (response == b''):
            time.sleep(0.001)
            response = self._sock.recv(2)
        if (response[0:1] != b'0'):
            logging.info(response)
            return b'\xFF'
        if (len(response) > 1):
            if (filename == ""):
                filename = name
            try:
                try:
                    os.remove(filename)
                except:
                    pass
                os.makedirs(os.path.dirname(os.getcwd() + "/" + filename), exist_ok=True)
                fileIO = open(filename, "ab")
                self._sock.send(b'0')
                count = int(response[1:])
                if (self._is_encrypted):
                    for i in range(count):
                        data = self._sock.recv(100000)
                        while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                            data += self._sock.recv(100000)
                        fileIO.write(blosc.decompress(Salsa20.new(self._key, random.randbytes(8)).decrypt(data[:len(data) - 6])))
                        if (i != (count - 1)):
                            self._sock.send(b'0')
                    fileIO.close()
                else:
                    for i in range(count):
                        data = self._sock.recv(100000)
                        while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                            data += self._sock.recv(100000)
                        fileIO.write(blosc.decompress(data[:len(data) - 6]))
                        if (i != (count - 1)):
                            self._sock.send(b'0')
                    fileIO.close()
                return b''
            except Exception as e:
                logging.info(e)
        else:
            data = self._sock.recv(100000)
            while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                time.sleep(0.001)
                data += self._sock.recv(100000)
            if (self._is_encrypted):
                data = Salsa20.new(self._key, random.randbytes(8)).decrypt(data[:len(data) - 6])
            else:
                data = data[:len(data) - 6]
            return blosc.decompress(data)

    # Gets a list of files and directories
    def ls(self, mode=0, subdir=""):
        if ((mode == 0) & (subdir == "")):
            subdir = b'./'
        elif (mode == 1):
            subdir = b'\xEE'
        else:
            subdir = bytes(subdir, "utf8")
        if (self._is_encrypted):
            self._sock.send(Salsa20.new(self._key, random.randbytes(8)).encrypt(b'01' + subdir + (b'\xFF' * (254 - len(subdir)))))
        else:
            self._sock.send(b'01' + subdir + (b'\xFF' * (254 - len(subdir))))
        data = self._sock.recv(100000)
        while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
            time.sleep(0.001)
            data += self._sock.recv(100000)
        if (self._is_encrypted):
            data = Salsa20.new(self._key, random.randbytes(8)).decrypt(data[:len(data) - 6])
        else:
            data = data[:len(data) - 6]
        return eval(data)

    # Deletes file, folder, or memory
    def rm(self, path):
        if (self._is_encrypted):
            self._sock.send(Salsa20.new(self._key, random.randbytes(8)).encrypt(b'12' + bytes(path, "utf8") + (b'\xFF' * (254 - len(path)))))
        else:
            self._sock.send(b'12' + bytes(path, "utf8") + (b'\xFF' * (254 - len(path))))
        response = self._sock.recv(1)
        while (response == b''):
            time.sleep(0.001)
            response = self._sock.recv(1)
        return (response == b'0')

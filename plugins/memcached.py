# coding=utf-8 author:wilson
import time
import threading
from comm.printers import printGreen
import socket

socket.setdefaulttimeout(8)


class memcache_burp(object):
    def __init__(self, c):
        '''
        模仿代码：https://github.com/ysrc/F-Scrack
        :param c:
        '''
        self.config = c
        self.lock = threading.Lock()
        self.result = []

    def run(self, ipdict, pinglist, threads, file):
        # memeche
        if len(ipdict['memcache']):
            for ip in ipdict['memcache']:
                printGreen("[+] %s memcache at %s port has memcached_information_leak\r\n" % (
                    ip.split(':')[0], ip.split(':')[1]))
                self.result.append("[+] %s memcache at %s port has memcached_information_leak\r\n" % (
                    ip.split(':')[0], ip.split(':')[1]))
            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'memcache': ['xxx:11211']}
    pinglist = ['xxx:123123']
    test = memcache_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

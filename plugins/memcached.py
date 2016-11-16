# coding=utf-8 author:wilson
import time
import threading
from comm.printers import printGreen
from multiprocessing.dummy import Pool
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

    def ldap_creak(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            s.send("stats\r\n")
            result = s.recv(1024)
            if "version" in result:
                self.lock.acquire()
                printGreen("[+] %s memcache at %s port has memcached_information_leak\r\n" % (ip, port))
                self.result.append("[+] %s memcache at %s port has memcached_information_leak\r\n" % (ip, port))
                self.lock.release()
        except Exception, e:
            print "[!] err: %s" % e
        finally:
            s.close()

    def run(self, ipdict, pinglist, threads, file):
        if len(ipdict['memcache']):
            print "[*] crack memcache  now..."
            print "[*] start memcache  %s" % time.ctime()
            starttime = time.time()
            pool = Pool(threads)
            for ip in ipdict['memcache']:
                pool.apply_async(func=self.ldap_creak, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))
            pool.close()
            pool.join()
            print "[*] stop memcache serice  %s" % time.ctime()
            print "[*] crack memcache done,it has Elapsed time:%s " % (time.time() - starttime)
            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'memcache': ['xxx:11211']}
    pinglist = ['xxx']
    test = memcache_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

# coding=utf-8
import time
import threading
from comm.printers import printGreen
from multiprocessing.dummy import Pool
import socket, binascii

socket.setdefaulttimeout(8)
try:
    import ldap
except:
    print "没有安装ldap库!暂不扫描ldap"


class ldap_burp(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []

    def ldap_connect(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            data = binascii.a2b_hex("301502010160100201030409416e6f6e796d6f75738000")
            s.send(data)
            result = s.recv(1024)
            if "invalid" in result:
                return 1
        except:
            return 0

    def ldap_creak(self, ip, port):
        try:
            flag = self.ldap_connect(ip, port)
            if flag == 1:
                self.lock.acquire()
                printGreen("[+] %s ldap at %s port allow simple bind\r\n" % (ip, port))
                self.result.append("[+] %s ldap at %s port allow simple bind\r\n" % (ip, port))
                self.lock.release()
        except Exception, e:
            print e
            pass

    def run(self, ipdict, pinglist, threads, file):
        if len(ipdict['ldap']):
            print "[*] crack ldap  now..."
            print "[*] start ldap  %s" % time.ctime()
            starttime = time.time()
            pool = Pool(threads)
            for ip in ipdict['ldap']:
                pool.apply_async(func=self.ldap_creak, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))
            pool.close()
            pool.join()
            print "[*] stop ldap serice  %s" % time.ctime()
            print "[*] crack ldap done,it has Elapsed time:%s " % (time.time() - starttime)
            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'ldap': ['xxxx:389']}
    pinglist = ['xxxxx']
    test = ldap_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

# coding=utf-8 author:wilson
import time
import threading
from comm.printers import printGreen
from multiprocessing.dummy import Pool
import socket, binascii

socket.setdefaulttimeout(8)


class snmp_burp(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []

    # public 登入
    def snmp_connect_public(self, ip):
        try:
            # udp 连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_address = (ip, 161)
            # "7075626c6963" public
            message = binascii.a2b_hex(
                "302902010004067075626c6963a01c020400a15f37020100020100300e300c06082b060102010101000500")
            sock.sendto(message, server_address)
            data, server = sock.recvfrom(4096)
            # print data
            if "public" in data:
                return 1
        except Exception, e:
            return 0
        finally:
            sock.close()

    # private 登入
    def snmp_connect_private(self, ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_address = (ip, 161)
            # "70726976617465" private
            message = binascii.a2b_hex(
                "302a020100040770726976617465a01c020400ea74b3020100020100300e300c06082b060102010101000500")
            sock.sendto(message, server_address)
            data, server = sock.recvfrom(4096)
            # print data
            if "private" in data:
                return 1
        except Exception, e:
            return 0
        finally:
            sock.close()

    def snmp_l(self, ip, port):
        try:
            flag = self.snmp_connect_public(ip)
            if flag == 1:
                self.lock.acquire()
                printGreen("[+] %s snmp  has weaken password!!-----%s\r\n" % (ip, "public"))
                self.result.append("[+] %s snmp  has weaken password!!-----%s\r\n" % (ip, "public"))
                self.lock.release()
                return
            else:
                self.lock.acquire()
                print "[*] test %s snmp's scan fail with public" % (ip)
                self.lock.release()

            flag = self.snmp_connect_private(ip)
            if flag == 1:
                self.lock.acquire()
                printGreen("[+] %s snmp  has weaken password!!-----%s\r\n" % (ip, "private"))
                self.result.append("[+] %s snmp  has weaken password!!-----%s\r\n" % (ip, "private"))
                self.lock.release()
                return
            else:
                self.lock.acquire()
                print "[*] test %s snmp's scan fail with private" % (ip)
                self.lock.release()
        except Exception, e:
            print "[!] err : %s" % e

    def run(self, ipdict, pinglist, threads, file):
        print "[*] crack snmp now..."
        print "[*] start crack snmp %s" % time.ctime()
        starttime = time.time()
        pool = Pool(threads)
        for ip in pinglist:
            pool.apply_async(func=self.snmp_l, args=(str(ip).split(':')[0], ""))

        pool.close()
        pool.join()

        print "[*] stop crack snmp %s" % time.ctime()
        print "[*] crack snmp done,it has Elapsed time:%s " % (time.time() - starttime)

        for i in xrange(len(self.result)):
            self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'snmp': ['xxx:161']}
    pinglist = ['xxx']
    test = snmp_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

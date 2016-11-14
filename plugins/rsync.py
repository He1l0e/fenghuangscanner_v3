# -*- coding: utf-8 -*-
from comm.printers import printPink, printGreen
from multiprocessing.dummy import Pool
from Queue import Queue
import time
import threading
import sys
import socket

socket.setdefaulttimeout(10)
sys.path.append("../")


class rsync_burp(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.sp = Queue()

    def rsync_connect(self, ip, port):
        creak = 0
        try:
            payload = '\x40\x52\x53\x59\x4e\x43\x44\x3a\x20\x33\x31\x2e\x30\x0a'
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(10)
            s.connect((ip, int(port)))
            s.sendall(payload)
            time.sleep(2)
            initinfo = s.recv(400)
            if "RSYNCD" in initinfo:
                s.sendall("\x0a")
                time.sleep(2)
            modulelist = s.recv(200)
            key = False
            if len(modulelist) > 0:
                for i in modulelist.split("\n"):
                    # 无模块的就不报漏洞
                    if i != "" and i.find("@RSYNCD") < 0:
                        key = True
                        break
                if key:
                    self.lock.acquire()
                    printGreen("[+] %s rsync at %s port  maybe allow anonymous login" % (ip, port))
                    self.result.append("[+] %s rsync at %s port  maybe allow anonymous login" % (ip, port))
                    self.lock.release()
        except Exception, e:
            print e

    def rsync_creak(self, ip, port):
        try:
            self.rsync_connect(ip, port)
        except Exception, e:
            print e

    def run(self, ipdict, pinglist, threads, file):
        if len(ipdict['rsync']):
            print "[*] crack rsync  now..."
            print "[*] start crack rsync  %s" % time.ctime()
            starttime = time.time()

            pool = Pool(threads)

            for ip in ipdict['rsync']:
                pool.apply_async(func=self.rsync_creak, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))
            pool.close()
            pool.join()

            print "[*] stop rsync serice  %s" % time.ctime()
            print "[*] crack rsync done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    from comm.config import *

    c = config()
    ipdict = {'rsync': ['xxx:873']}
    pinglist = ['xxx']
    test = rsync_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

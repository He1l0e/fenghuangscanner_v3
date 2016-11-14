# coding=utf-8
import time
import threading
from comm.printers import printGreen
from multiprocessing.dummy import Pool
import socket, binascii

socket.setdefaulttimeout(8)  # 设置了全局默认超时时间


class mongodb_burp(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/mongodb.conf")

    def mongoDB(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, int(port)))
            data = binascii.a2b_hex(
                "3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000")
            s.send(data)
            result = s.recv(1024)
            if "ismaster" in result:
                getlog_data = binascii.a2b_hex(
                    "480000000200000000000000d40700000000000061646d696e2e24636d6400000000000100000021000000026765744c6f670010000000737461727475705761726e696e67730000")
                s.send(getlog_data)
                result = s.recv(1024)
                if "totalLinesWritten" in result:
                    self.lock.acquire()
                    printGreen('[+] %s mongodb service at %s allow login Anonymous login!!\r\n' % (ip, port))
                    self.result.append('[+] %s mongodb service at %s allow login Anonymous login!!\r\n' % (ip, port))
                    self.lock.release()
        except Exception, e:
            print "[!] %s" % e
            pass

    def run(self, ipdict, pinglist, threads, file):
        if len(ipdict['mongodb']):
            print "[*] crack mongodb  now..."
            print "[*] start crack mongodb  %s" % time.ctime()
            starttime = time.time()

            pool = Pool(threads)

            for ip in ipdict['mongodb']:
                pool.apply_async(func=self.mongoDB, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))

            pool.close()
            pool.join()
            print "[*] stop mongoDB serice  %s" % time.ctime()
            print "[*] crack mongoDB done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'mongodb': ['xxxx:27017']}
    pinglist = ['xxxx']
    test = mongodb_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

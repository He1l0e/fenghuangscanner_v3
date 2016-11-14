# coding=utf-8
import time
import threading
from comm.printers import printGreen
from Queue import Queue
from multiprocessing.dummy import Pool
import socket

socket.setdefaulttimeout(8)  # 设置了全局默认超时时间


class redis_burp(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/redis.conf")
        self.sp = Queue()

    def redis(self, password, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            s.send("AUTH %s\r\n" % (password))
            result = s.recv(1024)
            if '+OK' in result:
                return 1
        except Exception, e:
            return 0

    def redisexp(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            s.send("INFO\r\n")
            result = s.recv(1024)
            if "redis_version" in result:
                self.lock.acquire()
                printGreen('[+] %s redis service at %s allow login Anonymous login!!\r\n' % (ip, port))
                self.result.append('[+] %s redis service at %s allow login Anonymous login!!\r\n' % (ip, port))
                self.lock.release()
            elif "Authentication" in result:
                for password in self.lines:
                    flag = self.redis(password, ip, port)
                    if flag == 1:
                        self.lock.acquire()
                        printGreen('[+] %s redis service at %s port has weakpass:%s' % (ip, port, password))
                        self.result.append('[+] %s redis service at %s port has weakpass:%s' % (ip, port, password))
                        self.lock.release()
                        break
                    else:
                        self.lock.acquire()
                        print "[*] %s's redis service 's %s login fail " % (ip, password)
                        self.lock.release()
        except Exception, e:
            print "[!] %s" % e
            pass
        self.sp.task_done()

    def run(self, ipdict, pinglist, threads, file):
        if len(ipdict['redis']):
            print "[*] crack redis  now..."
            print "[*] start crack redis  %s" % time.ctime()
            starttime = time.time()

            pool = Pool(threads)
            for ip in ipdict['redis']:
                pool.apply_async(func=self.redisexp, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))

            pool.close()
            pool.join()

            print "[*] stop redis serice  %s" % time.ctime()
            print "[*] crack redis done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'redis': ['127.0.0.1:6379']}
    pinglist = ['xxxx']
    test = redis_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

# coding=utf-8 author:wilson
import time
import threading
from multiprocessing.dummy import Pool
from comm.printers import printGreen
from ftplib import FTP


class ftp_burp(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/ftp.conf")

    def ftp_connect(self, ip, username, password, port):
        try:
            ftp = FTP()
            ftp.connect(ip, str(port), timeout=8)
            ftp.login(user=username, passwd=password)
            # 登入成功
            return 1
        except Exception, e:
            if e[0] == 61 or e[0] == "timed out":
                # 连接超时
                return 2
            else:
                # 登入失败
                return 0
        finally:
            ftp.close()

    def ftp_l(self, ip, port):
        try:
            for data in self.lines:
                username = data.split(':')[0]
                password = data.split(':')[1]
                flag = self.ftp_connect(ip, username, password, port)
                if flag == 1:
                    self.lock.acquire()
                    printGreen(
                        "[+] %s ftp at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.result.append(
                        "[+] %s ftp at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.lock.release()
                    break
                elif flag == 2:
                    self.lock.acquire()
                    print "[!] %s's ftp service can't connect or connect timeout" % (ip)
                    self.lock.release()
                    break
                else:
                    self.lock.acquire()
                    print "[*] %s's ftp service 's %s:%s login fail " % (ip, username, password)
                    self.lock.release()

        except:
            pass

    def run(self, ipdict, pinglist, threads, file):
        if len(ipdict['ftp']):
            print "[*] crack ftp  now..."
            print "[*] start crack ftp  %s" % time.ctime()
            starttime = time.time()

            pool = Pool(threads)

            for ip in ipdict['ftp']:
                pool.apply_async(func=self.ftp_l, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))
            pool.close()
            pool.join()

            print "[*] stop ftp serice  %s" % time.ctime()
            print "[*] crack ftp done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'ftp': ['xxx:21']}
    pinglist = ['xxx.60']
    test = ftp_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

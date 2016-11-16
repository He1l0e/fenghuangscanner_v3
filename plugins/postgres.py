# coding=utf-8 author:wilson
import time
import threading
from comm.printers import printGreen
from multiprocessing.dummy import Pool
import socket, hashlib

socket.setdefaulttimeout(8)  # 设置了全局默认超时时间


class postgres_burp(object):
    def __init__(self, c):
        '''
        模仿代码：https://github.com/ysrc/F-Scrack
        :param c:
        只适应于某版本，有些版本不能用
        '''
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/postgres.conf")

    def make_response(self, username, password, salt):
        pu = hashlib.md5(password + username).hexdigest()
        buf = hashlib.md5(pu + salt).hexdigest()
        return 'md5' + buf

    def postgresql_connect(self, ip, username, password, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
        except:
            # 连接超时
            return 3
        try:
            packet_length = len(username) + 7 + len(
                "\x03user  database postgres application_name psql client_encoding UTF8  ")
            p = "%c%c%c%c%c\x03%c%cuser%c%s%cdatabase%cpostgres%capplication_name%cpsql%cclient_encoding%cUTF8%c%c" % (
                0, 0, 0, packet_length, 0, 0, 0, 0, username, 0, 0, 0, 0, 0, 0, 0, 0)
            sock.send(p)
            packet = sock.recv(1024)
            if "ont exist" in packet:
                # 用户不存在
                return 3
            if packet[0] == 'R':
                a = str([packet[4]])
                b = int(a[4:6], 16)
                authentication_type = str([packet[8]])
                c = int(authentication_type[4:6], 16)
                if c == 5:
                    salt = packet[9:]
                else:

                    return 3
            else:
                # 协议版本不对
                return 3
            lmd5 = self.make_response(username, password, salt)
            packet_length1 = len(lmd5) + 5 + len('p')
            pp = 'p%c%c%c%c%s%c' % (0, 0, 0, packet_length1 - 1, lmd5, 0)
            sock.send(pp)
            packet1 = sock.recv(1024)
            if packet1[0] == "R":
                return 1
        except Exception, e:
            # 发送错误
            print "[!] err: %s" % e
            return 3

    def postgresql(self, ip, port):
        try:
            for data in self.lines:
                username = data.split(':')[0]
                password = data.split(':')[1]
                flag = self.postgresql_connect(ip, username, password, port)
                if flag == 3:
                    break
                if flag == 1:
                    self.lock.acquire()
                    printGreen(
                        "[+] %s postgresql at %s has weaken password!!-------%s:%s\r\n" % (
                            ip, port, username, password))
                    self.result.append(
                        "[+] %s postgresql at %s has weaken password!!-------%s:%s\r\n" % (
                            ip, port, username, password))
                    self.lock.release()
                    break
        except:
            pass

    def run(self, ipdict, pinglist, threads, file):
        if len(ipdict['postgres']):
            print "[*] crack postgres now..."
            print "[*] start crack postgres %s" % time.ctime()
            starttime = time.time()

            pool = Pool(threads)
            for ip in ipdict['postgres']:
                pool.apply_async(func=self.postgresql, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))

            pool.close()
            pool.join()

            print "[+] stop crack postgres %s" % time.ctime()
            print "[+] crack postgres done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'postgres': ['xxxx:5432']}
    pinglist = ['127.0.0.1']
    test = postgres_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

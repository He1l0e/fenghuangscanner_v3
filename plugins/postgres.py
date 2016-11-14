# coding=utf-8
'''
import time
import threading
from comm.printers import printGreen
from multiprocessing.dummy import Pool
import socket, hashlib

socket.setdefaulttimeout(8)  # 设置了全局默认超时时间


class mysql_burp(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/postgres.conf")

    def make_response(self, buf, username, password, salt):
        pu = hashlib.md5(password + username).hexdigest()
        print pu + salt
        buf = hashlib.md5(pu + salt).hexdigest()
        return 'md5' + buf

    def postgresql_connect(self, ip, username, password, port):

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
        except:
            return 3
        try:
            packet_length = len(username) + 7 + len(
                "\x03user  database postgres application_name psql client_encoding UTF8  ")
            p = "%c%c%c%c%c\x03%c%cuser%c%s%cdatabase%cpostgres%capplication_name%cpsql%cclient_encoding%cUTF8%c%c" % (
                0, 0, 0, packet_length, 0, 0, 0, 0, username, 0, 0, 0, 0, 0, 0, 0, 0)
            sock.send(p)
            packet = sock.recv(1024)
            psql_salt = []
            if packet[0] == 'R':
                a = str([packet[4]])
                b = int(a[4:6], 16)
                authentication_type = str([packet[8]])
                c = int(authentication_type[4:6], 16)
                if c == 5: psql_salt = packet[9:]
            else:
                return 3
            buf = []
            salt = psql_salt
            lmd5 = self.make_response(buf, username, password, salt)
            packet_length1 = len(lmd5) + 5 + len('p')
            pp = 'p%c%c%c%c%s%c' % (0, 0, 0, packet_length1 - 1, lmd5, 0)
            sock.send(pp)
            packet1 = sock.recv(1024)
            if packet1[0] == "R":
                return 1
        except Exception, e:
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
        except Exception, e:
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
    ipdict = {'postgres': ['127.0.0.1:5432']}
    pinglist = ['127.0.0.1']
    test = mysql_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

'''
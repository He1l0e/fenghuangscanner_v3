# coding=utf-8 author:wilson
import time
import threading
from comm.printers import printGreen
from multiprocessing.dummy import Pool
import socket, binascii

socket.setdefaulttimeout(8)  # 设置了全局默认超时时间


class mssql_burp(object):
    def __init__(self, c):
        '''
        模仿代码：https://github.com/ysrc/F-Scrack
        :param c:
        只适应于某版本，sql 2014 以上不能使用
        '''
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/mssql.conf")

    def mssql_connect(self, ip, username, password, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, int(port)))
        except:
            print "[!] connect error"
            sock.close()
            return 2

        try:
            hh = binascii.b2a_hex(ip)
            husername = binascii.b2a_hex(username)
            lusername = len(username)
            lpassword = len(password)
            ladd = len(ip) + len(str(port)) + 1
            hladd = hex(ladd).replace('0x', '')
            hpwd = binascii.b2a_hex(password)
            pp = binascii.b2a_hex(str(port))
            address = hh + '3a' + pp
            hhost = binascii.b2a_hex(ip)
            data = "0200020000000000123456789000000000000000000000000000000000000000000000000000ZZ5440000000000000000000000000000000000000000000000000000000000X3360000000000000000000000000000000000000000000000000000000000Y373933340000000000000000000000000000000000000000000000000000040301060a09010000000002000000000070796d7373716c000000000000000000000000000000000000000000000007123456789000000000000000000000000000000000000000000000000000ZZ3360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000Y0402000044422d4c6962726172790a00000000000d1175735f656e676c69736800000000000000000000000000000201004c000000000000000000000a000000000000000000000000000069736f5f31000000000000000000000000000000000000000000000000000501353132000000030000000000000000"
            data1 = data.replace(data[16:16 + len(address)], address)
            data2 = data1.replace(data1[78:78 + len(husername)], husername)
            data3 = data2.replace(data2[140:140 + len(hpwd)], hpwd)
            if lusername >= 16:
                data4 = data3.replace('0X', str(hex(lusername)).replace('0x', ''))
            else:
                data4 = data3.replace('X', str(hex(lusername)).replace('0x', ''))
            if lpassword >= 16:
                data5 = data4.replace('0Y', str(hex(lpassword)).replace('0x', ''))
            else:
                data5 = data4.replace('Y', str(hex(lpassword)).replace('0x', ''))
            hladd = hex(ladd).replace('0x', '')
            data6 = data5.replace('ZZ', str(hladd))
            data7 = binascii.a2b_hex(data6)
            sock.send(data7)
            packet = sock.recv(1024)
            if 'master' in packet:
                return 1
            else:
                print "[*] %s's mssql service 's %s:%s login fail " % (ip, username, password)
        except Exception, e:
            print "[!] err :%s" % e
            return 3
        finally:
            sock.close()

    def mssq1(self, ip, port):
        try:
            for data in self.lines:
                username = data.split(':')[0]
                password = data.split(':')[1]
                flag = self.mssql_connect(ip, username, password, port)
                if flag == 2:
                    break
                if flag == 1:
                    self.lock.acquire()
                    printGreen(
                        "[+] %s mssql at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.result.append(
                        "[+] %s mssql at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.lock.release()
                    break
        except Exception, e:
            pass

    def run(self, ipdict, pinglist, threads, file):
        if len(ipdict['mssql']):
            print "[*] crack sql serice  now..."
            print "[*] start crack sql serice  %s" % time.ctime()
            starttime = time.time()
            pool = Pool(threads)
            for ip in ipdict['mssql']:
                pool.apply_async(func=self.mssq1, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))
            pool.close()
            pool.join()

            print "[*] stop crack sql serice  %s" % time.ctime()
            print "[*] crack sql serice  done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'mssql': ['xxx:1433']}
    pinglist = ['xxxx']
    test = mssql_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

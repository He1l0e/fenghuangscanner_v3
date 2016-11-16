# coding=utf-8 author:wilson
import time
import threading
from comm.printers import printGreen
from multiprocessing.dummy import Pool
import socket, binascii, re, hashlib, struct

socket.setdefaulttimeout(8)  # 设置了全局默认超时时间


class mysql_burp(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/mysql.conf")

    def get_scramble(self, packet):
        scramble, plugin = '', ''
        try:
            tmp = packet[15:]
            m = re.findall("\x00?([\x01-\x7F]{7,})\x00", tmp)
            if len(m) > 3: del m[0]
            scramble = m[0] + m[1]
        except:
            return '', ''
        try:
            plugin = m[2]
        except:
            pass
        return plugin, scramble

    def get_hash(self, password, scramble):
        hash_stage1 = hashlib.sha1(password).digest()
        hash_stage2 = hashlib.sha1(hash_stage1).digest()
        to = hashlib.sha1(scramble + hash_stage2).digest()
        reply = [ord(h1) ^ ord(h3) for (h1, h3) in zip(hash_stage1, to)]
        hash = struct.pack('20B', *reply)
        return hash

    def get_auth_data(self, user, password, scramble, plugin):
        user_hex = binascii.b2a_hex(user)
        pass_hex = binascii.b2a_hex(self.get_hash(password, scramble))
        data = "85a23f0000000040080000000000000000000000000000000000000000000000" + user_hex + "0014" + pass_hex
        if plugin: data += binascii.b2a_hex(
            plugin) + "0055035f6f73076f737831302e380c5f636c69656e745f6e616d65086c69626d7973716c045f7069640539323330360f5f636c69656e745f76657273696f6e06352e362e3231095f706c6174666f726d067838365f3634"
        len_hex = hex(len(data) / 2).replace("0x", "")
        auth_data = len_hex + "000001" + data
        return binascii.a2b_hex(auth_data)

    def mysql_connect(self, ip, username, password, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            packet = sock.recv(254)
            plugin, scramble = self.get_scramble(packet)
            if not scramble:
                return 3
        except Exception, e:
            print "[!] error: %s" % e
            sock.close()
            return 3
        try:
            auth_data = self.get_auth_data(username, password, scramble, plugin)
            sock.send(auth_data)
            result = sock.recv(1024)
            if result == "\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00":
                return 1
            else:
                self.lock.acquire()
                print "[*] %s's mysql service 's %s:%s login fail " % (ip, username, password)
                self.lock.release()
        except:
            pass
        finally:
            sock.close()

    def mysq1(self, ip, port):
        try:
            for data in self.lines:
                username = data.split(':')[0]
                password = data.split(':')[1]
                flag = self.mysql_connect(ip, username, password, port)
                if flag == 3:
                    break
                if flag == 1:
                    self.lock.acquire()
                    printGreen(
                        "[+] %s mysql at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.result.append(
                        "[+] %s mysql at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                    self.lock.release()
                    break
        except:
            pass

    def run(self, ipdict, pinglist, threads, file):
        if len(ipdict['mysql']):
            print "[*] crack mysql now..."
            print "[*] start crack mysql %s" % time.ctime()
            starttime = time.time()

            pool = Pool(threads)
            for ip in ipdict['mysql']:
                pool.apply_async(func=self.mysq1, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))

            pool.close()
            pool.join()

            print "[+] stop crack mysql %s" % time.ctime()
            print "[+] crack mysql done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'mysql': ['xxxx:3306']}
    pinglist = ['xxx']
    test = mysql_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

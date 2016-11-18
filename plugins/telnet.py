# coding=utf-8 author:wilson
import time
import threading
from comm.printers import printGreen
from multiprocessing.dummy import Pool
import telnetlib, re


class telnet_burp(object):
    def __init__(self, c):
        '''
        模仿代码：https://github.com/ysrc/F-Scrack
        :param c:
        '''
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/telnet.conf")

    def telnet_connect(self, ip, port, user, pass_, timeout=4):
        user_match = "(?i)(login|username)"
        pass_match = '(?i)(password|pass)'
        login_match = '#|\$|>'
        try:
            tn = telnetlib.Telnet(ip, port, timeout=timeout)
            # tn.set_debuglevel(3)
            time.sleep(0.5)
            os = tn.read_some()
            # os 为版本信息
            # print os

            # 版本信息匹配搭配用户名，爆破用户名加密码
            if re.search(user_match, os, re.IGNORECASE):
                try:
                    tn.write(str(user) + '\r\n')
                    tn.read_until(pass_match, timeout)
                    tn.write(str(pass_) + '\r\n')
                    login_info = tn.read_until(login_match, timeout=timeout)
                    tn.close()
                    if re.search(login_match, login_info, re.IGNORECASE):
                        printGreen("[+] %s telnet at %s port has weaken password!!-------%s:%s\r\n" % (
                            ip, port, user, pass_))
                        self.result.append("[+] %s telnet at %s port has weaken password!!-------%s:%s\r\n" % (
                            ip, port, user, pass_))
                        self.lock.release()
                    else:
                        self.lock.acquire()
                        print "[*] %s's telnet service 's %s:%s login fail " % (ip, user, pass_)
                        self.lock.release()
                except Exception, e:
                    print "[!] err:%s" % e
                    pass

            # 版本信息匹配搭配密码，只爆破密码
            elif re.search(pass_match, os, re.IGNORECASE):
                tn.read_until(pass_match, timeout=timeout)
                tn.write(str(pass_) + '\r\n')
                login_info = tn.read_until(login_match, timeout=timeout)
                # print login_info
                tn.close()
                if re.search(login_match, login_info):
                    self.lock.acquire()
                    printGreen(
                        "[+] %s telnet at %s port has weaken password!!-------%s\r\n" % (ip, port, pass_))
                    self.result.append(
                        "[+] %s telnet at %s port has weaken password!!-------%s\r\n" % (ip, port, pass_))
                    self.lock.release()
                else:
                    self.lock.acquire()
                    print "[*] %s's telnet service 's %s login fail " % (ip, pass_)
                    self.lock.release()
            # 版本信息中未匹配到有效信息
            else:
                # 获取第二个信息，为认证信息
                try:
                    info = tn.read_until(user_match, timeout=timeout)
                except:
                    return 3
                # print info
                # 认证信息匹配搭配用户名，爆破用户名加密码
                if re.search(user_match, info, re.IGNORECASE):
                    try:
                        tn.write(str(user) + '\r\n')
                        tn.read_until(pass_match, timeout=timeout)
                        tn.write(str(pass_) + '\r\n')
                        login_info = tn.read_until(login_match, timeout=timeout)
                        tn.close()
                        # print login_info
                        if re.search(login_match, login_info):
                            self.lock.acquire()
                            printGreen("[+] %s telnet at %s port has weaken password!!-------%s:%s\r\n" % (
                                ip, port, user, pass_))
                            self.result.append("[+] %s telnet at %s port has weaken password!!-------%s:%s\r\n" % (
                                ip, port, user, pass_))
                            self.lock.release()
                            return 1
                        else:
                            self.lock.acquire()
                            print "[*] %s's telnet service 's %s:%s login fail " % (ip, user, pass_)
                            self.lock.release()
                    except Exception, e:
                        print "[!] err: %s" % e
                        return 3
                # 认证信息匹配搭配密码，只爆破密码
                elif re.search(pass_match, info, re.IGNORECASE):
                    tn.read_until(pass_match, timeout=2)
                    tn.write(str(pass_) + '\r\n')
                    login_info = tn.read_until(login_match, timeout=timeout)
                    tn.close()
                    if re.search(login_match, login_info):
                        self.lock.acquire()
                        printGreen(
                            "[+] %s telnet at %s port has weaken password!!-------%s\r\n" % (ip, port, pass_))
                        self.result.append(
                            "[+] %s telnet at %s port has weaken password!!-------%s\r\n" % (ip, port, pass_))
                        self.lock.release()
                    else:
                        self.lock.acquire()
                        print "[*] %s's telnet service 's %s login fail " % (ip, user)
                        self.lock.release()
        except Exception, e:
            print "[!] err: %s" % e
            return 0
        finally:
            tn.close()

    def telnet_creak(self, ip, port):
        try:
            for data in self.lines:
                username = data.split(':')[0]
                password = data.split(':')[1]
                flag = self.telnet_connect(ip, port, username, password)
                if flag in [0, 1, 3]:
                    break
        except Exception, e:
            print "[!] err: %s" % e
            pass

    def run(self, ipdict, pinglist, threads, file):
        if len(ipdict['telnet']):
            print "[*] crack telnet  now..."
            print "[*] start telnet  %s" % time.ctime()
            starttime = time.time()
            pool = Pool(threads)
            for ip in ipdict['telnet']:
                pool.apply_async(func=self.telnet_creak, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))
            pool.close()
            pool.join()
            print "[*] stop telnet serice  %s" % time.ctime()
            print "[*] crack telnet done,it has Elapsed time:%s " % (time.time() - starttime)
            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'telnet': ['xxx:23']}
    pinglist = ['x']
    test = telnet_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

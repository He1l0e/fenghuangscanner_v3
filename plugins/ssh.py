# coding=utf-8 author:wilson
import time
import threading, re
from multiprocessing.dummy import Pool
from comm.printers import printGreen, printRed

try:
    import paramiko

    isinstall = True
except:
    isinstall = False

import platform, subprocess, os, signal, time


def command(cmd, timeout=8):
    '''
    带超时的执行命令
    :param cmd:
    :param timeout:
    :return:
    '''
    is_linux = platform.system() in ['Linux']
    p = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True,
                         preexec_fn=os.setsid if is_linux else None)
    t_beginning = time.time()
    seconds_passed = 0
    while True:
        if p.poll() is not None:
            break
        seconds_passed = time.time() - t_beginning
        if timeout and seconds_passed > timeout:
            if is_linux:
                os.killpg(p.pid, signal.SIGTERM)
            else:
                p.terminate()
            raise TimeoutError(cmd, timeout, p)
        time.sleep(0.1)
    return p.stdout.read()


try:
    if re.search("usage:", command("ssh"), re.IGNORECASE):
        if re.search("expect", command("expect"), re.IGNORECASE):
            # 有ssh命令
            has_sshclient = True
    else:
        has_sshclient = False
except:
    has_sshclient = False


class TimeoutError(Exception):
    pass


class ssh_burp(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.lines = self.config.file2list("conf/ssh.conf")

    def ssh_connect(self, ip, username, password, port):
        '''
        连接ssh 安装了库就用库，没用安装而且是linux就用bash来登入
        :param ip:
        :param username:
        :param password:
        :param port:
        :return:
        '''
        if isinstall == True:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port, username=username, password=password)
                return 1
            except Exception, e:
                if e[0] == 'Authentication failed.':
                    return 0
                else:
                    return 2
            finally:
                client.close()
        else:
            try:
                # login_match = '#|\$|>' 这样有误报
                refused_match = 'refused'
                denied_match = 'denied'
                exe_file = '''#!/usr/bin/expect -f

set user %s
set password %s
set host %s
set port %s
set timeout 4
spawn ssh -p $port $user@$host
expect "*assword:*"
send "$password\\r"
expect eof''' % (username, password, ip, port)
                f = open('./bin/sshlogin', 'w')
                f.write(exe_file)
                f.close()

                msg = command("./bin/sshlogin")

                if re.search(refused_match, msg, re.IGNORECASE):
                    # 连接拒绝
                    return 2
                elif not re.search(denied_match, msg, re.IGNORECASE):
                    # 没有denied 说明登入成功
                    return 1
                else:
                    # 登入失败
                    return 0

            except Exception, e:
                print "[!] err:%s" % e
                return 0

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
        if isinstall == False and has_sshclient == False:
            printRed("[!] 抱歉没有安装paramiko库，而且不能存在ssh客户端，所以ssh模块无效，如果你要爆破ssh弱口令，需要安装 paramiko 1.15.2")
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
    ipdict = {'ssh': ['xxxx:22']}
    pinglist = ['xxx']
    test = ssh_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

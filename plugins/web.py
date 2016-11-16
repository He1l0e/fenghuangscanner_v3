# coding=utf-8 author:wilson
import threading
from comm.printers import printGreen
from multiprocessing.dummy import Pool
import time
import base64
import urllib2


class web_burp(object):
    def __init__(self, c):
        self.config = c
        self.lock = threading.Lock()
        self.result = []
        self.tomcatlines = self.config.file2list("conf/tomcat.conf")
        self.weblines = self.config.file2list("conf/web.conf")

    def weblogin(self, url, ip, port, username, password):
        try:
            # header = {}
            login_pass = username + ':' + password
            hash = 'Basic ' + base64.encodestring(login_pass).replace("\n", "")
            # header['Authorization'] = 'Basic ' + base64.encodestring(login_pass)
            # header base64.encodestring 会多加一个回车号
            # header['Authorization'] = header['Authorization'].replace("\n", "")
            request = urllib2.Request(url)
            request.add_header('Authorization', hash)
            response = urllib2.urlopen(request, timeout=8)
            # r = requests.get(url, headers=header, timeout=8)
            code = response.getcode()
            if code == 200:
                self.result.append(
                    "[+] %s service at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                self.lock.acquire()
                printGreen(
                    "[+] %s service at %s has weaken password!!-------%s:%s\r\n" % (ip, port, username, password))
                self.lock.release()
                return 1
            else:
                self.lock.acquire()
                print "[*] %s service 's %s:%s login fail " % (ip, username, password)
                self.lock.release()
        except:
            self.lock.acquire()
            print "[*] %s service 's %s:%s login fail " % (ip, username, password)
            self.lock.release()
        return 0

    def webmain(self, ip, port):
        # iis_put vlun scann
        try:
            url = 'http://' + ip + ':' + str(port) + '/' + str(time.time()) + '.txt'
            r = urllib2.Request(url, data='hi~')
            r.get_method = lambda: 'PUT'
            response = urllib2.urlopen(r, timeout=10)
            code = response.getcode()
            if code == 201:
                self.lock.acquire()
                printGreen('[+] %s has iis_put vlun at %s\r\n' % (ip, port))
                self.lock.release()
                self.result.append('[+] %s has iis_put vlun at %s\r\n' % (ip, port))
        except Exception, e:
            print e
            pass

        # burp 401 web
        try:
            url = 'http://' + ip + ':' + str(port)
            url_get = url + '/manager/html'
            # tomcat
            r = urllib2.Request(url_get)
            # 基础认证
            r2 = urllib2.Request(url)

            try:
                re = urllib2.urlopen(r, timeout=10)
                r_code = re.getcode()
            except urllib2.URLError, e:
                r_code = e.code

            try:
                re2 = urllib2.urlopen(r2, timeout=10)
                r2_code = re2.getcode()
            except urllib2.URLError, e:
                r2_code = e.code

            if r_code == 401:
                for data in self.tomcatlines:
                    username = data.split(':')[0]
                    password = data.split(':')[1]
                    flag = self.weblogin(url_get, ip, port, username, password)
                    if flag == 1:
                        break

            elif r2_code == 401:
                for data in self.weblines:
                    username = data.split(':')[0]
                    password = data.split(':')[1]
                    flag = self.weblogin(url, ip, port, username, password)
                    if flag == 1:
                        break
            else:
                pass

        except Exception, e:
            pass

    def run(self, ipdict, pinglist, threads, file):
        if len(ipdict['http']):
            print "[*] start test web burp at %s" % time.ctime()
            starttime = time.time()

            pool = Pool(threads)

            for ip in ipdict['http']:
                pool.apply_async(func=self.webmain, args=(str(ip).split(':')[0], int(str(ip).split(':')[1])))
            pool.close()
            pool.join()

            print "[*] stop test iip_put&&scanner web paths at %s" % time.ctime()
            print "[*] test iip_put&&scanner web paths done,it has Elapsed time:%s " % (time.time() - starttime)

            for i in xrange(len(self.result)):
                self.config.write_file(contents=self.result[i], file=file)


if __name__ == '__main__':
    import sys

    sys.path.append("../")
    from comm.config import *

    c = config()
    ipdict = {'http': ['xxx:80']}
    pinglist = ['xxx']
    test = web_burp(c)
    test.run(ipdict, pinglist, 50, file="../result/test")

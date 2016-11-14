# coding=utf-8
__author__ = 'wilson'
import sys

sys.path.append("../")
from comm.config import *
from comm.printers import printPink, printRed, printGreen

import threading
from threading import Thread
from Queue import Queue
import platform
from subprocess import Popen, PIPE
import re
import time
import socket

socket.setdefaulttimeout(10)  # 设置了全局默认超时时间


class portscan():
    """docstring for ClassName"""

    def __init__(self, c, user_ports):
        self.config = c
        self.PROBES = [
            '\r\n\r\n',
            'GET / HTTP/1.0\r\n\r\n',
            'GET / \r\n\r\n',
            '\x01\x00\x00\x00\x01\x00\x00\x00\x08\x08',
            '\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
            '\x03\0\0\x0b\x06\xe0\0\0\0\0\0',
            '\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0',
            '\x80\x9e\x01\x03\x01\x00u\x00\x00\x00 \x00\x00f\x00\x00e\x00\x00d\x00\x00c\x00\x00b\x00\x00:\x00\x009\x00\x008\x00\x005\x00\x004\x00\x003\x00\x002\x00\x00/\x00\x00\x1b\x00\x00\x1a\x00\x00\x19\x00\x00\x18\x00\x00\x17\x00\x00\x16\x00\x00\x15\x00\x00\x14\x00\x00\x13\x00\x00\x12\x00\x00\x11\x00\x00\n\x00\x00\t\x00\x00\x08\x00\x00\x06\x00\x00\x05\x00\x00\x04\x00\x00\x03\x07\x00\xc0\x06\x00@\x04\x00\x80\x03\x00\x80\x02\x00\x80\x01\x00\x80\x00\x00\x02\x00\x00\x01\xe4i<+\xf6\xd6\x9b\xbb\xd3\x81\x9f\xbf\x15\xc1@\xa5o\x14,M \xc4\xc7\xe0\xb6\xb0\xb2\x1f\xf9)\xe8\x98',
            '\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`\0\x15\0\x12\0\x09\0\x14\0\x11\0\x08\0\x06\0\x03\x01\0',
            '< NTP/1.2 >\n',
            '< NTP/1.1 >\n',
            '< NTP/1.0 >\n',
            '\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\04\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))',
            '\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00',
            '\0\0\0\0\x44\x42\x32\x44\x41\x53\x20\x20\x20\x20\x20\x20\x01\x04\0\0\0\x10\x39\x7a\0\x01\0\0\0\0\0\0\0\0\0\0\x01\x0c\0\0\0\0\0\0\x0c\0\0\0\x0c\0\0\0\x04',
            '\x01\xc2\0\0\0\x04\0\0\xb6\x01\0\0\x53\x51\x4c\x44\x42\x32\x52\x41\0\x01\0\0\x04\x01\x01\0\x05\0\x1d\0\x88\0\0\0\x01\0\0\x80\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x08\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x01\0\0\x40\0\0\0\x40\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x02\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x08\0\0\0\x01\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\x01\x04\0\0\x01\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x20\x20\x20\x20\x20\x20\x20\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe4\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f',
            '\x41\0\0\0\x3a\x30\0\0\xff\xff\xff\xff\xd4\x07\0\0\0\0\0\0test.$cmd\0\0\0\0\0\xff\xff\xff\xff\x1b\0\0\0\x01serverStatus\0\0\0\0\0\0\0\xf0\x3f\0'
        ]
        self.SIGNS = self.config.file2list("conf/signs.conf")
        self.ports = []
        self.getports(user_ports)
        self.lock = threading.Lock()
        self.pinglist = []
        self.q = Queue()
        self.sp = Queue()
        self.signs = self.prepsigns()

        self.ipdict = {}
        self.ipdict['ldap'] = []
        self.ipdict['mysql'] = []
        self.ipdict['mssql'] = []
        self.ipdict['ftp'] = []
        self.ipdict['ssh'] = []
        self.ipdict['smb'] = []
        self.ipdict['vnc'] = []
        self.ipdict['pop3'] = []
        self.ipdict['rsync'] = []
        self.ipdict['http'] = []
        self.ipdict['https'] = []
        self.ipdict['mongodb'] = []
        self.ipdict['postgres'] = []
        self.ipdict['redis'] = []
        self.ipdict['ssl'] = []
        self.ipdict['Unknown'] = []

    # 获取扫描端口列表
    def getports(self, user_ports):
        if user_ports == '':
            self.ports = [1, 9, 13, 17, 30, 37, 49, 53, 70, 106, 113, 119, 125, 135, 139, 146, 161, 163, 179, 199, 222,
                          259, 264, 280, 301, 306, 311, 340, 366, 389, 425, 427, 458, 481, 497, 500, 524, 541, 548, 563,
                          587, 593, 625, 631, 636, 646, 648, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
                          777, 783, 787, 808, 843, 873, 880, 888, 898, 981, 987, 990, 995, 1007, 1102, 1117, 1119, 1126,
                          1141, 1145, 1154, 1169, 1183, 1192, 1201, 1213, 1236, 1244, 1259, 1277, 1287, 1296, 1322,
                          1328, 1334, 1352, 1417, 1443, 1455, 1461, 1494, 1503, 1521, 1524, 1533, 1556, 1580, 1583,
                          1594, 1600, 1641, 1658, 1666, 1700, 1723, 1755, 1761, 1801, 1805, 1812, 1875, 1900, 1914,
                          1935, 1947, 1974, 1984, 2013, 2030, 2038, 2065, 2068, 2103, 2111, 2119, 2121, 2126, 2135,
                          2144, 2170, 2179, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2375, 2399, 2401,
                          2492, 2500, 2522, 2525, 2557, 2638, 2710, 2725, 2800, 2809, 2811, 2869, 2875, 2920, 2998,
                          3003, 3011, 3013, 3017, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3283, 3306, 3333, 3351,
                          3367, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3703, 3737, 3766, 3784, 3809,
                          3812, 3814, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986,
                          3995, 3998, 4045, 4111, 4129, 4224, 4242, 4279, 4321, 4343, 4440, 4449, 4550, 4567, 4662,
                          4848, 4998, 5009, 5030, 5033, 5054, 5080, 5087, 5120, 5190, 5200, 5214, 5269, 5280, 5298,
                          5357, 5405, 5414, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5718,
                          5730, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5915, 5922, 5925, 5950, 5952, 6009, 6025,
                          6059, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6580, 6646, 6689,
                          6692, 6699, 6779, 6792, 6839, 6881, 6901, 6969, 7004, 7007, 7019, 7025, 7070, 7100, 7103,
                          7106, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7800, 7911, 8031, 8042, 8045,
                          8093, 8200, 8222, 8254, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8654, 8701,
                          8800, 8873, 8888, 8899, 8994, 9040, 9050, 9071, 9220, 9290, 9415, 9418, 9485, 9500, 9535,
                          9575, 9618, 9666, 9898, 9900, 9917, 9929, 9968, 10012, 10022, 10082, 10180, 10215, 10243,
                          10566, 10621, 10626, 10778, 11211, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 14000,
                          14238, 15000, 15660, 15742, 16012, 16016, 16018, 16080, 16113, 17017, 17877, 17988, 18040,
                          18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20828,
                          21571, 22022, 22222, 22939, 23502, 24444, 24800, 26214, 27000, 27017, 27715, 28017, 28201,
                          30000, 30718, 30951, 31038, 31337, 33354, 33899, 35500, 38292, 40193, 40911, 41511, 42510,
                          44176, 44501, 45100, 48080, 49163, 49165, 49167, 49400, 50006, 50070, 50300, 50389, 50500,
                          50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55555, 55600, 57294,
                          57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
                          8983, 50075, 50090, 50075, 50030, 50060, 3, 4, 6, 7, 19, 20, 21, 22, 23, 24, 25, 26, 32, 33,
                          42, 43, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 109, 110, 111, 143, 144, 211, 212,
                          254, 255, 256, 406, 407, 416, 417, 443, 444, 445, 464, 465, 512, 513, 514, 515, 543, 544, 545,
                          554, 555, 616, 617, 666, 667, 668, 800, 801, 900, 901, 902, 903, 911, 912, 992, 993, 999,
                          1000, 1001, 1002, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029,
                          1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044,
                          1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059,
                          1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074,
                          1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089,
                          1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1104, 1105, 1106, 1107,
                          1108, 1110, 1111, 1112, 1113, 1114, 1121, 1122, 1123, 1124, 1130, 1131, 1132, 1137, 1138,
                          1147, 1148, 1149, 1151, 1152, 1163, 1164, 1165, 1166, 1174, 1175, 1185, 1186, 1187, 1198,
                          1199, 1216, 1217, 1218, 1233, 1234, 1247, 1248, 1271, 1272, 1300, 1301, 1309, 1310, 1311,
                          1433, 1434, 1500, 1501, 1687, 1688, 1717, 1718, 1719, 1720, 1721, 1782, 1783, 1839, 1840,
                          1862, 1863, 1864, 1971, 1972, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
                          2008, 2009, 2010, 2020, 2021, 2022, 2033, 2034, 2035, 2040, 2041, 2042, 2043, 2045, 2046,
                          2047, 2048, 2049, 2099, 2100, 2105, 2106, 2107, 2160, 2161, 2190, 2191, 2381, 2382, 2383,
                          2393, 2394, 2601, 2602, 2604, 2605, 2607, 2608, 2701, 2702, 2717, 2718, 2909, 2910, 2967,
                          2968, 3000, 3001, 3005, 3006, 3007, 3030, 3031, 3260, 3261, 3268, 3269, 3300, 3301, 3322,
                          3323, 3324, 3325, 3369, 3370, 3371, 3372, 3389, 3390, 3689, 3690, 3800, 3801, 3826, 3827,
                          3828, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4125, 4126, 4443, 4444, 4445, 4446, 4899,
                          4900, 5000, 5001, 5002, 5003, 5004, 5050, 5051, 5060, 5061, 5100, 5101, 5102, 5221, 5222,
                          5225, 5226, 5431, 5432, 5678, 5679, 5800, 5801, 5802, 5810, 5811, 5900, 5901, 5902, 5903,
                          5904, 5906, 5907, 5910, 5911, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999,
                          6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6100, 6101, 6565, 6566, 6567, 6666, 6667,
                          6668, 6669, 6788, 6789, 7000, 7001, 7002, 7200, 7201, 7777, 7778, 7920, 7921, 7937, 7938,
                          7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8080, 8081, 8082, 8083,
                          8084, 8085, 8086, 8087, 8088, 8089, 8090, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8290,
                          8291, 8292, 8651, 8652, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9080, 9081, 9090, 9091,
                          9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9201, 9202, 9203, 9204, 9205, 9206, 9207,
                          9502, 9503, 9593, 9594, 9595, 9876, 9877, 9878, 9943, 9944, 9998, 9999, 10000, 10001, 10002,
                          10003, 10004, 10009, 10010, 10024, 10025, 10616, 10617, 10628, 10629, 11110, 11111, 13782,
                          13783, 14441, 14442, 15002, 15003, 15004, 16000, 16001, 16992, 16993, 20221, 20222, 25734,
                          25735, 27352, 27353, 27355, 27356, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
                          32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 34571, 34572, 34573,
                          44442, 44443, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49175,
                          49176, 49999, 50000, 50001, 50002, 50003, 55055, 55056, 56737, 56738]


        else:
            try:
                if user_ports.find(",") > 0:
                    for port in user_ports.split(','):
                        self.ports.append(int(port))

                elif user_ports.find("-") > 0:
                    startport = int(user_ports.split('-')[0])
                    endport = int(user_ports.split('-')[1])
                    for i in xrange(startport, endport + 1):
                        self.ports.append(i)
                else:
                    self.ports.append(int(user_ports))
            except:
                printRed('[!] not a valid ports given. you should put ip like 22,80,1433 or 22-1000')
                exit()

    # ping扫描函数
    def pinger(self):
        while True:
            ip = self.q.get()
            if platform.system() == 'Linux':
                p = Popen(['ping', '-c 2', ip], stdout=PIPE)
                m = re.search('(\d)\sreceived', p.stdout.read())
                try:
                    if m.group(1) != '0':
                        self.pinglist.append(ip)
                        self.lock.acquire()
                        printRed("%s is live!!\r\n" % ip)
                        self.lock.release()
                except:
                    pass

            if platform.system() == 'Darwin':
                import commands
                p = commands.getstatusoutput("ping -c 2 " + ip)
                m = re.findall('ttl', p[1])
                try:
                    if m:
                        self.pinglist.append(ip)
                        self.lock.acquire()
                        printRed("%s is live!!\r\n" % ip)
                        self.lock.release()
                except:
                    pass

            if platform.system() == 'Windows':
                p = Popen('ping -n 2 ' + ip, stdout=PIPE)
                m = re.findall('TTL', p.stdout.read())
                if m:
                    self.pinglist.append(ip)
                    self.lock.acquire()
                    printRed("%s is live!!\r\n" % ip)
                    self.lock.release()
            self.q.task_done()

    def pingscan(self, isping, threads, ips):
        starttime = time.time()
        friststarttime = time.time()
        print "[*] start Scanning at %s" % time.ctime()
        # isping=='no' 就禁ping扫描
        # 默认ping 扫描
        if isping == 'yes':
            print "Scanning for live machines..."
            for i in xrange(threads):
                t = Thread(target=self.pinger)
                t.setDaemon(True)
                t.start()
            for ip in ips:
                self.q.put(ip)

            self.q.join()

        else:
            self.pinglist = ips

        if len(self.pinglist) == 0:
            print "not find any live machine - -|||"
            exit()

        print "[*] Scanning for live machines done,it has Elapsed time:%s " % (time.time() - starttime)

    def prepsigns(self):
        signlist = []
        for item in self.SIGNS:
            (label, pattern) = item.split('|', 2)
            sign = (label, pattern)
            signlist.append(sign)
        return signlist

    def matchbanner(self, banner, slist):
        # print banner
        for item in slist:
            p = re.compile(item[1])
            # print item[1]
            if p.search(banner) != None:
                return item[0]
        return 'Unknown'

    # 扫端口及其对应服务类型函数
    def scanports(self):
        while True:
            ip, port = self.sp.get()
            # print ip,port
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 判断端口的服务类型
            service = 'Unknown'
            try:
                s.connect((ip, port))
            except:
                self.sp.task_done()
                continue

            try:
                result = s.recv(256)
                service = self.matchbanner(result, self.signs)
            except:
                for probe in self.PROBES:
                    # print probe
                    try:
                        s.close()
                        sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sd.settimeout(5)
                        sd.connect((ip, port))
                        sd.send(probe)
                    except:
                        continue
                    try:
                        result = sd.recv(256)
                        service = self.matchbanner(result, self.signs)
                        if service != 'Unknown':
                            break
                    except:
                        continue

            if service not in self.ipdict:
                self.ipdict[service] = []
                self.ipdict[service].append(ip + ':' + str(port))
                self.lock.acquire()
                printRed("%s opening %s\r\n" % (ip, port))
                self.lock.release()
            else:
                self.ipdict[service].append(ip + ':' + str(port))
                self.lock.acquire()
                printRed("%s opening %s\r\n" % (ip, port))
                self.lock.release()

            self.sp.task_done()

    def portsscan(self, threads, file):
        print "Scanning ports now..."
        print "[*] start Scanning live machines' ports at %s" % time.ctime()
        starttime = time.time()

        for i in xrange(threads):
            st = Thread(target=self.scanports)
            st.setDaemon(True)
            st.start()

        for scanip in self.pinglist:
            for port in self.ports:
                self.sp.put((scanip, port))
        self.sp.join()
        print "[*] Scanning ports done,it has Elapsed time:%s " % (time.time() - starttime)
        # 将服务端口 信息 记录文件
        for name in self.ipdict.keys():
            if len(self.ipdict[name]):
                contents = str(name) + ' service has:\n' + '       ' + str(self.ipdict[name]) + '\n'
                self.config.write_file(contents=contents, file=file)


            # 处理没有识别的服务

    def handleunknown(self):
        for ip in self.ipdict['Unknown']:
            # print ip
            try:
                if str(ip).split(':')[1] == '389':
                    self.ipdict['ldap'].append(ip)
                if str(ip).split(':')[1] == '445':
                    self.ipdict['smb'].append(ip)
                if str(ip).split(':')[1] in ['3306', '3307', '3308', '3309']:
                    self.ipdict['mysql'].append(ip)
                if str(ip).split(':')[1] == '1433':
                    self.ipdict['mssql'].append(ip)
                if str(ip).split(':')[1] in ['10022', '22']:
                    self.ipdict['ssh'].append(ip)
                if str(ip).split(':')[1] == '27017':
                    self.ipdict['mongodb'].append(ip)
                if str(ip).split(':')[1] == '110':
                    self.ipdict['pop3'].append(ip)
                if str(ip).split(':')[1] == '5432':
                    self.ipdict['postgres'].append(ip)
                if str(ip).split(':')[1] == '443':
                    self.ipdict['ssl'].append(ip)
                if str(ip).split(':')[1] == '873':
                    self.ipdict['rsync'].append(ip)
                if str(ip).split(':')[1] == '6379':
                    self.ipdict['redis'].append(ip)
                #	            if str(ip).split(':')[1]=='21':
                #	                    self.ipdict['ftp'].append(ip)
            except Exception as e:
                print e
            # 处理被识别为http的mongo
        for ip in self.ipdict['http']:
            if str(ip).split(':')[1] == '27017':
                self.ipdict['http'].remove(ip)
                self.ipdict['mongodb'].append(ip)

    def run(self, isping, threads, ips, file):
        self.pingscan(isping, threads, ips)
        self.portsscan(threads, file)
        self.handleunknown()

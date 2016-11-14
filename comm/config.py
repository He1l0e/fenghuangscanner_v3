# coding=utf-8
__author__ = 'wilson'
from IPy import IP
from comm.printers import printRed


class config(object):
    def get_ip_list(self, ip):
        '''
        获取ip类别，模仿代码：https://github.com/ysrc/F-Scrack
        支持ip(192.168.1.1)，ip段（192.168.1），ip范围指定（192.168.1.1-192.168.1.254）,
            ip列表文件（ip.ini），最多限制一次可扫描65535个IP。
        :return: iplist
        '''
        ip_list = []
        iptonum = lambda x: sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])
        numtoip = lambda x: '.'.join([str(x / (256 ** i) % 256) for i in range(3, -1, -1)])
        if '-' in ip:
            ip_range = ip.split('-')
            ip_start = long(iptonum(ip_range[0]))
            ip_end = long(iptonum(ip_range[1]))
            ip_count = ip_end - ip_start
            if ip_count >= 0 and ip_count <= 65536:
                for ip_num in range(ip_start, ip_end + 1):
                    ip_list.append(numtoip(ip_num))
            else:
                print '[!] -h wrong format'
        elif '.ini' in ip:
            ip_config = open(ip, 'r')
            for ip in ip_config:
                ip_list.extend(self.get_ip_list(ip.strip()))
            ip_config.close()
        else:
            ip_split = ip.split('.')
            net = len(ip_split)
            if net == 2:
                for b in range(1, 255):
                    for c in range(1, 255):
                        ip = "%s.%s.%d.%d" % (ip_split[0], ip_split[1], b, c)
                        ip_list.append(ip)
            elif net == 3:
                for c in range(1, 255):
                    ip = "%s.%s.%s.%d" % (ip_split[0], ip_split[1], ip_split[2], c)
                    ip_list.append(ip)
            elif net == 4:
                ip_list.append(ip)
            else:
                print "[!] -h wrong format"
        return ip_list

    def getips(self, ip):
        '''
        久的获取ip列表 依靠ipy库
        :param ip:
        :return:
        '''
        iplist = []
        try:
            if "-" in ip.split(".")[3]:
                startnum = int(ip.split(".")[3].split("-")[0])
                endnum = int(ip.split(".")[3].split("-")[1])
                for i in range(startnum, endnum):
                    iplist.append("%s.%s.%s.%s" % (ip.split(".")[0], ip.split(".")[1], ip.split(".")[2], i))
            else:
                ips = IP(ip)
                for i in ips:
                    iplist.append(str(i))

            return iplist

        except:
            printRed("[!] not a valid ip given. you should put ip like 192.168.1.0/24, 192.168.0.0/16,192.168.0.1-200")
            exit()

    def file2list(self, file):
        '''
        文件转字典
        :param file:
        :return:
        '''
        iplist = []
        try:
            fh = open(file)
            for ip in fh.readlines():
                ip = ip.strip()
                iplist.append(ip)
            fh.close()
            return iplist
        except Exception, e:
            print e
            exit()

    def write_file(self, file, contents):
        '''
        最近写文件
        :param file:
        :param contents:
        :return:
        '''
        f2 = open(file, 'a+')
        f2.write(contents)
        f2.close()


if __name__ == '__main__':
    c = config()
    print c.get_ip_list("127.0.0.1")

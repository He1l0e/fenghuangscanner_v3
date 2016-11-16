# coding=utf-8 author:wilson
__author__ = 'wilson'

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

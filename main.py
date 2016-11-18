# coding=utf-8 author:wilson
__author__ = 'wilson'
from comm.config import config
from comm.portscan import *
from factorys.pluginFactory import *
from optparse import OptionParser
import sys

reload(sys)
sys.setdefaultencoding('utf-8')

if __name__ == '__main__':
    # 接受cmd参数
    parser = OptionParser(description='ports&*weak password scanner. company:mogu security. teams:xdsec. author: wilson ')
    parser.add_option('--ip', dest="ip", type="string",
                      help='必填,支持ip(192.168.1.1),ip段(192.168.1),(192.168.1.1-192.168.1.254),ip列表文件(ip.ini)')
    parser.add_option("--threads", action="store", dest="threads", type=int, default=50,
                      help='线程数, 选填默认50')
    parser.add_option("--P", action="store", dest="isping", type="string", default='yes',
                      help='是否ping扫描,默认ping扫描,可以--P n来禁ping扫描')
    parser.add_option("--p", action="store", dest="user_ports", type="string", default='',
                      help='端口设置，选填 支持--p 21,80,445 or 22-1000')
    parser.add_option("--file", action="store", dest="file", type="string",
                      help='保存结果到文件，选填 默认以ip的名字为文件名')
    (options, args) = parser.parse_args()
    ip = options.ip
    filename = options.file

    # 实例化config类
    c = config()

    # 获取ip列表
    if ip:
        ips = c.get_ip_list(ip)
        file = "result/%s.txt" % ip.replace("/", "")
    elif filename:
        ips = c.file2list(filename)
        filename = filename.split("/")[-1]
        file = "result/%s.txt" % filename
    else:
        print "[!] error args, try -h"
        sys.exit()

    isping = options.isping
    user_posts = options.user_ports
    threads = options.threads

    # 端口扫描
    p = portscan(c, user_posts)
    p.run(isping, threads, ips, file)

    # 插件弱口令扫描
    plugins = pluginFactory(c)
    for pluginname in plugins.pluginList:
        # print pluginname
        if pluginname:
            pluginname.run(p.ipdict, p.pinglist, threads, file)

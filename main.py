# coding=utf-8 author:wilson
__author__ = 'wilson'
import argparse
from comm.config import config
from comm.portscan import *
from factorys.pluginFactory import *

if __name__ == '__main__':
    # 接受cmd参数
    parser = argparse.ArgumentParser(description='ports&*weak password scanner. teams:xdsec.  author: wilson ')
    parser.add_argument('--ip', action="store", required=False, dest="ip", type=str,
                        help='必填,支持ip(192.168.1.1),ip段(192.168.1),(192.168.1.1-192.168.1.254),ip列表文件(ip.ini)')
    parser.add_argument("--threads", action="store", required=False, dest="threads", type=int, default=50,
                        help='线程数, 选填默认50')
    parser.add_argument("--P", action="store", required=False, dest="isping", type=str, default='yes',
                        help='是否ping扫描,默认ping扫描')
    parser.add_argument("--p", action="store", required=False, dest="user_ports", type=str, default='',
                        help='端口设置，选填 支持--p 21,80,445 or 22-1000')
    parser.add_argument("--file", action="store", required=False, dest="file", type=str,
                        help='保存结果到文件，选填 默认以ip的名字为文件名')

    args = parser.parse_args()
    ip = args.ip
    filename = args.file

    # 实例化config类
    c = config()

    # 获取ip列表
    if ip:
        ips = c.get_ip_list(ip)
        file = "result/%s.txt" % args.ip.replace("/", "")
    elif filename:
        ips = c.file2list(filename)
        filename = filename.split("/")[-1]
        file = "result/%s.txt" % filename
    else:
        print "[!] error args"
        exit()

    isping = args.isping
    user_posts = args.user_ports
    threads = args.threads

    # 端口扫描
    p = portscan(c, user_posts)
    p.run(isping, threads, ips, file)

    # 插件弱口令扫描
    plugins = pluginFactory(c)
    for pluginname in plugins.pluginList:
        # print pluginname
        if pluginname:
            pluginname.run(p.ipdict, p.pinglist, threads, file)

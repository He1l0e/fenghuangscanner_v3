# coding=utf-8 author:wilson
__author__ = "wilson"
import sys

sys.path.append("../")

from plugins.ftp import *
from plugins.ldapd import *
from plugins.memcached import *
from plugins.mongodb import *
from plugins.mssql import *
from plugins.mysql import *
from plugins.postgres import *
from plugins.redisexp import *
from plugins.rsync import *
from plugins.smb import *
from plugins.snmp import *
from plugins.ssh import *
from plugins.ssltest import *
# from plugins.vnc import *
from plugins.telnet import *
from plugins.web import *


def ftpburp(c):
    t = ftp_burp(c)
    return t


def ldapburp(c):
    t = ldap_burp(c)
    return t


def memcacheburp(c):
    t = memcache_burp(c)
    return t


def mongodbburp(c):
    t = mongodb_burp(c)
    return t


def mssqlburp(c):
    t = mssql_burp(c)
    return t


def mysqlburp(c):
    t = mysql_burp(c)
    return t


def postgresburp(c):
    t = postgres_burp(c)
    return t


def redisburp(c):
    t = redis_burp(c)
    return t


def rsyncburp(c):
    t = rsync_burp(c)
    return t


def smbburp(c):
    t = smb_burp(c)
    return t


def snmpburp(c):
    t = snmp_burp(c)
    return t


def sshburp(c):
    t = ssh_burp(c)
    return t


def sslburp(c):
    t = ssl_burp(c)
    return t


def telnetburp(c):
    t = telnet_burp(c)
    return t


'''
def vncburp(c):
    t = vnc_burp(c)
    return t
'''


def webburp(c):
    t = web_burp(c)
    return t


# 类
class pluginFactory():
    def __init__(self, c):
        self.pluginList = []
        self.config = c
        self.pluginCategory = {
            "ftp": ftpburp,
            "ldap": ldapburp,
            "memcache": memcacheburp,
            "mongodb": mongodbburp,
            "mssql": mssqlburp,
            "mysql": mysqlburp,
            "postgres": postgresburp,
            "redis": redisburp,
            "rsync": rsyncburp,
            "smb": smbburp,
            "snmp": snmpburp,
            "ssh": sshburp,
            "ssltest": sslburp,
            "telnet": telnetburp,
            # "vnc": vncburp,
            "web": webburp,
        }
        self.get_pluginList()

    def get_pluginList(self):
        for name in self.pluginCategory:
            # 实例化每个类
            result_t = self.pluginCategory.get(name)(self.config)
            self.pluginList.append(result_t)

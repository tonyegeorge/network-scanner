import net
import os
import inspect
from configparser import RawConfigParser, NoSectionError
from pprint import pprint

__THIS_DIR = os.path.dirname(os.path.abspath(
    inspect.getframeinfo(inspect.currentframe()).filename
))
__CONFIG_PATH = os.path.join(__THIS_DIR, "net.cfg")

__CONFIG_SECTION_GUAC = "guacamole"
# __hosts = net.hosts()

class db(net.mysql_db):

    def __init__(self, **kargs):

        parser = RawConfigParser()
        parser.read(globals()['__CONFIG_PATH'])
        try:
            self.host = parser.get(
                globals()['__CONFIG_SECTION_GUAC'], "db_host"
            )
        except NoSectionError as e:
            self.host = None

        print(self.host)
        try:
            self.user = parser.get(
                globals()['__CONFIG_SECTION_GUAC'], "db_user"
            )
        except NoSectionError as e:
            self.user = None

        try:
            self.passwd = parser.get(
                globals()['__CONFIG_SECTION_GUAC'], "db_pass"
            )
        except NoSectionError as e:
            self.passwd = None

        try:
            self.db = parser.get(
                globals()['__CONFIG_SECTION_GUAC'], "db_name"
            )
        except NoSectionError as e:
            self.db = None

        try:
            self.port = parser.get(
                globals()['__CONFIG_SECTION_GUAC'], "db_port"
            )
        except NoSectionError as e:
            self.port = 3306

        if 'host' in kargs.keys():
            self.host= kargs['host']

        if 'passwd' in kargs.keys():
            self.passwd = kargs['passwd']

        if 'db' in kargs.keys():
            self.db= kargs['db']

        if 'port' in kargs.keys():
            self.port = kargs['port']

        # if self.host and self.user and self.passwd and self.db and self.port:
        #     self.connect()
        print('*' * 40)

        print(self.host, self.user, self.passwd, self.port)

        # self.db = net.mysql_db(host=self)
        # self.db = net.mysql_db(
        #     host=self.host,
        #     user=self.user,
        #     passwd=self.passwd,
        #     db=self.db,
        #     port=self.port)


class connection(object):

    class attribute(object):
        def __init__(self):
            self.attribute_name = None
            self.attribute_value = None

    def __init__(self):
        self.connection_id = None
        self.connection_name = None
        self.parent_id = None
        self.protocol = None
        self.proxy_port = None
        self.proxy_hostname = None
        self.proxy_encryption_method = None
        self.max_connections = None
        self.max_connections_per_user = None
        self.connection_weight = None
        self.failover_only = None
        self.attributes = []

class host(net.host):
    def __init__(self):
        super().__init__()
    def rdp():
        pass

class hosts(net.hosts):
    def __init__(self):
        super().__init__()


config = net.config()

print(config.nmap.ip_range)
print(config.ldap.user)
sys.exit()

# print('*' * 40)
# x = db()
# x.connect()
# x.tables()
# pprint(x.tables(True))
# x.cursor.execute("SELECT * FROM guacamole_connection LIMIT 1")
# p = hosts()
# pprint(p.hosts)
# p.scan_ldap()

# s = net.ldap()
# print(s.filt)
# for z in p.hosts:
#     print(str(z))
# print(x.user)








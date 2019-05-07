
import sys
import os
import re
import json
import inspect
import sqlite3
import pymysql
import nmap as nm
import ldap3
from pprint import pprint
from datetime import datetime, timedelta
from IPy import IP
from configparser import RawConfigParser, NoSectionError

__THIS_DIR = os.path.dirname(os.path.abspath(
    inspect.getframeinfo(inspect.currentframe()).filename
))
__CONFIG_PATH = os.path.join(__THIS_DIR, "net.cfg")
__NET_DB_PATH = os.path.join(__THIS_DIR, "net.db")
__CONFIG_SECTION_NMAP = "nmap"
__CONFIG_SECTION_LDAP = "ldap"
__CONFIG_SECTION_MYSQL = "mysql"
__NMAP_DEFAULT_PORTS = '5899-5940,3389,23,22'
__NMAP_DEFAULT_ARGUMENTS = '-O -sV'
__NMAP_OPTIONS_NEEDING_ROOT = '-O -sS'

class mysql_db:

    def __init__(self, **kargs):

        parser = RawConfigParser()
        parser.read(globals()['__CONFIG_PATH'])
        try:
            self.hostname = parser.get(
                globals()['__CONFIG_SECTION_MYSQL'], "hostname"
            )
        except NoSectionError as e:
            self.hostname = None
        try:
            self.username = parser.get(
                globals()['__CONFIG_SECTION_MYSQL'], "username"
            )
        except NoSectionError as e:
            self.username = None
        try:
            self.password = parser.get(
                globals()['__CONFIG_SECTION_MYSQL'], "password"
            )
        except NoSectionError as e:
            self.password = None
        try:
            self.database = parser.get(
                globals()['__CONFIG_SECTION_MYSQL'], "database"
            )
        except NoSectionError as e:
            self.database = None
        try:
            self.port = parser.get(
                globals()['__CONFIG_SECTION_MYSQL'], "port"
            )
        except NoSectionError as e:
            self.port = 3306

        if 'hostname' in kargs.keys():
            self.hostname = kargs['hostname']

        if 'password' in kargs.keys():
            self.password = kargs['password']

        if 'database' in kargs.keys():
            self.database = kargs['database']

        if 'port' in kargs.keys():
            self.port = kargs['port']

        if self.hostname and self.username and self.password and self.database and self.port:
            self.connect()

    def connect(self, **kargs):

        if 'hostname' in kargs.keys():
            self.hostname = kargs['hostname']

        if 'password' in kargs.keys():
            self.password = kargs['password']

        if 'database' in kargs.keys():
            self.database = kargs['database']

        if 'port' in kargs.keys():
            self.port = kargs['port']

        try:
            self.conn = pymysql.connect(
                host=self.hostname,
                user=self.username,
                passwd=self.password,
                db=self.database,
                port=self.port)
        except(
            mysql.connector.errors.InterfaceError,
            mysql.connector.errors.ProgrammingError,
        ) as e:
            self.error = e
            self.connection = None
            sys.exit()

        self.cursor = self.connection.cursor()

    def query(self, sql, params=[], multi=False):

        self.sql = re.sub(r'\s+', ' ', sql).replace('\n', ' ').strip()
        self.params = params
        self.multi = multi

        if multi is True:
            self.statement = []
            self.results = []
            try:
                for r1 in self.cursor.execute(
                    self.sql,
                    self.params,
                    multi=self.multi
                ):
                    self.statement.append(r1.statement)
                    if r1.with_rows:
                        self.results.append(r1.fetchall())
                    else:
                        self.results.append(r1.rowcount)

            except RuntimeError:
                pass
        else:
            self.cursor.execute(
                self.sql,
                self.params,
                multi=self.multi
            )
            self.statement = self.cursor.statement

            if self.cursor.with_rows:
                self.results = self.cursor.fetchall()
            else:
                self.results = self.cursor.rowcount

        return self.results


class net_db():
    """sqlite database for storing network data collected by nmap
    and ldap queries
    """
    def __init__(
        self,
        path=globals()['__NET_DB_PATH'],
        init=False
    ):
        self.path = path
        self.init = init
        self.conn = sqlite3.connect(
            self.path,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        self.cursor = self.conn.cursor()

        if self.init:
            self.drop_tables()
        self.create_tables()
        self.cursor.execute('PRAGMA journal_mode=wal')
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()

    def tables(self, columns=False):
        self.sql = "SELECT name FROM sqlite_master WHERE type='table'"
        self.results = self.cursor.execute(self.sql).fetchall()
        if columns:
            self.results = list(map(
                lambda x: (
                    x[0],
                    self.columns(x[0])
                ), self.results
            ))
        else:
            self.results = list(map( lambda x: x[0], self.results))
        return self.results

    def nmap(self, host=None, port=None, arguments=None):

        s, p = [], []

        if host:
            hosts = re.split('\s+,?\s*|\s*,?\s+', host)
            s.append('`host` IN ({})'.format(
                ', '.join(['?'] * len(hosts))
            ))
            p += hosts

        if port:
            s.append('`port` = ?')
            p.append(port)

        if arguments:
            s.append('`arguments` = ?')
            p.append(arguments)

        if s:
            self.sql = 'SELECT `data` FROM `nmap` WHERE {}'.format(
                ' AND '.join(s)
            )
            self.params = p
            self.results = self.cursor.execute(
                self.sql, self.params
            ).fetchall()
            for d in self.results:
                pprint(json.loads(d[0]))
        else:
            self.sql = "SELECT `host`, `port`, `arguments`, `command_line` FROM `nmap`"
            self.results = self.cursor.execute(self.sql).fetchall()
            fmt = '{0:15} {1:25} {2:12} {3}'
            print(fmt.format('host', 'ports', 'argumemnts', 'command_line'))
            print(fmt.format('----', '-----', '----------', '------------'))
            for h, p, a, c in self.results:
                print(fmt.format(h, p, a, c))

    def ldap(self, base=None, filter=None, attr=None):

        s, p = [], []

        if base:
            s.append('`base` = ?')
            p.append(base)

        if filter:
            s.append('`filter` = ?')
            p.append(filter)

        if attr:
            s.append('`attr` = ?')
            p.append(attr)

        if s:
            self.sql = 'select `data` from `ldap` where {}'.format(
                ' and '.join(s)
            )
            self.params = p
            self.results = self.cursor.execute(
                self.sql, self.params
            ).fetchall()
            for d in self.results:
                pprint(json.loads(d[0]))
        else:
            self.sql = "select `base`, `filter`, `attr` from `ldap`"
            self.results = self.cursor.execute(self.sql).fetchall()
            # fmt = '{0:80.80}'
            fmt = '{}'
            print(fmt.format('filter'))
            print(fmt.format('------'))
            for b, f, a in self.results:
                print(fmt.format(f))


    def columns(self, table):
        self.sql = "select * from {} limit 1".format(table)
        self.cursor.execute(self.sql)
        return list(map(
            lambda x: x[0], self.cursor.description
        ))

    def drop_tables(self):
        for table in self.tables():
            self.sql = 'drop table if exists {}'.format(table)
            self.cursor.execute(self.sql)

    def create_tables(self):

        sql = '''
        create table if not exists `nmap`(
        `host` varchar(20),
        `port` text,
        `arguments` text,
        `command_line` text,
        `data` json,
        `updated_at` timestamp default current_timestamp,
        unique(`host`, `port`, `arguments`)
       ) ;
        '''
        sql += '''
        create table if not exists `ldap`(
        `base` text not null,
        `filter` text not null,
        `attr` json,
        `data` json,
        `updated_at` timestamp default current_timestamp,
        unique(`base`, `filter`, `attr`)
       ) ;
        '''
        # sql = re.sub(r'\n\s*', '\n', _sql)
        # self.cursor.executescript(_sql)

        # add a trigger for each table to update the
        # modified timestamp
        _tables = self.tables()
        for table in _tables:
            t = self.columns(table)
            t = ['`{}`'.format(x) for x in t if x != 'updated_at']
            sql += '''
            drop trigger if exists `{0}_updated_at` ;
            create trigger `{0}_updated_at`
            after update of {1} on {0}
            for each row
            begin
            update `{0}` set `updated_at` = current_timestamp;
            end ;
            '''.format(table, ',\n'.join(t))

        self.sql = re.sub(r'\n\s*', '\n', sql)
        self.cursor.executescript(self.sql)
        self.conn.commit()

        return

    def foreign_keys(self, ptable, pkey):
        """ list the table names and fieled names of the the foreign keys that
        match the given table and field
        """
        result = []        # list for the result
        for table in self.tables:
            if table != ptable:  # exlude our subject table
                # query the foreign key list for this table
                self.sql = "pragma foreign_key_list({})".format(table)
                fkeys = self.cursor.execute(self.sql).fetchall()
                for fkey in fkeys:
                    # the 3rd field [2] is the name of the table
                    # the 4th field [3] is the foreign key
                    # while the 5th field [4] is the field that references
                    # our primary key
                    if fkey[2] == ptable and fkey[4] == pkey:
                        result.append([table, fkey[3]])
        return result



class nmap():


    def __init__(self):

        parser = RawConfigParser()
        parser.read(globals()['__CONFIG_PATH'])

        try:
            self.fqdn = parser.get(
                globals()['__CONFIG_SECTION_NMAP'], "fqdn"
            ).strip()
        except NoSectionError as e:
            self.fqdn = None

        try:
            self.ip_range = parser.get(
                globals()['__CONFIG_SECTION_NMAP'], "ip_range"
            ).strip()
        except NoSectionError as e:
                self.ip_range = '127.0.0.1'

        self.hosts = self.ip_range
        self.ports = globals()['__NMAP_DEFAULT_PORTS']
        self.arguments = globals()['__NMAP_DEFAULT_ARGUMENTS']
        self.days = 7

        self.nm = nm
        self.ps = self.nm.PortScanner()
        self.py = self.nm.PortScannerYield()

    def args(self, *args, **kargs):

        if len(args[0]) > 2:
            self.arguments = args[0][2]
        else:
            if 'arguments' in args[1].keys():
                self.arguments = args[1]['arguments']

        if len(args[0]) > 0:
            self.hosts = args[0][0]
        else:
            if 'hosts' in args[1].keys():
                self.hosts = args[1][0]

        if len(args[0]) > 1:
            self.ports = args[0][1]
        else:
            if 'ports' in args[1].keys():
                self.ports = args[1]['ports']

        if 'days' in args[1].keys():
            self.days = args[1]['days']

    @property
    def hosts(self):
        return self.__hosts

    @hosts.setter
    def hosts(self, hosts):
        def fix(h):
            try:
                IP(h)
            except :
                if len(h.split('.')) < 2:
                    try:
                        self.fqdn
                    except:
                        return h
                    if self.fqdn:
                        return str(h) + '.' + str(self.fqdn)
            return h

        __hosts = hosts.split()
        __hosts = list(map(lambda _: fix(_), __hosts))
        __hosts.sort()
        self.__hosts = ' '.join(__hosts)

    @property
    def ports(self):
        return self.__ports

    @ports.setter
    def ports(self, ports):
        if isinstance(ports, str):
            ports = list(map(
                lambda x: list(map(
                    lambda x: x.strip() ,x.split('-')
                )), re.split(r'\s*,\s*', ports)
            ))
        if isinstance(ports, list):
            if isinstance(ports[0], str):
                ports = list(map(
                    lambda x: x.strip(),
                    list(map(lambda x: x.split('-'), ports))
                ))
            for x in ports:
                x.sort()
            ports.sort()
            self.__ports = ','.join(list(dict.fromkeys(list(map(
                lambda x: '-'.join(x), ports
            )))))
        else:
            self.__ports = ports


    @property
    def arguments(self):
        return self.__arguments

    @arguments.setter
    def arguments(self, arguments):
        def l(a):
            return list(map(
                lambda x: x.strip(), filter(
                    lambda x: x.strip() != '', re.split('\B-', a)
                )
            ))
        __args = l(arguments)
        __ports = list(filter(lambda _: _.find('p') == 0, __args))
        if __ports:
            __args = list(filter(lambda x: x not in __ports, __args))
            _p = []
            for b in __ports:
                _p += list(map(
                    lambda x: x.replace(' ', ''),
                    re.split(r'\s*,\s*', b[1:].strip())
                ))
            if self.__ports:
                _p += list(map(
                    lambda x: x.replace(' ', ''),
                    re.split(r'\s*,\s*', self.__ports.strip())
                ))
            self.ports = _p

        __args.sort()
        __args_root = l(globals()['__NMAP_OPTIONS_NEEDING_ROOT'])
        __args_non_root = list(
            filter(lambda _: _ not in __args_root, __args)
        )
        self.__arguments = ' '.join(list(
            map(lambda _: '-' + str(_), __args)
        ))
        self.arguments_non_root = ' '.join(list(
            map(lambda _: '-' + str(_), __args_non_root)
        ))

    @property
    def days(self):
        return self.__days

    @days.setter
    def days(self, days):
        self.__days = days

    def read(self, hosts=None, ports=None, arguments=None, days=7):

        if not hosts:
            hosts = self.hosts
        if not ports:
            ports = self.ports
        if not arguments:
            arguments = self.arguments
        if not days:
            days = self.days

        self.sql, self.sql_param = [], []

        if hosts:
            hosts = re.split('\s+,?\s*|\s*,?\s+', host)
            self.sql.append('`host` IN ({})'.format(
                ', '.join(['?'] * len(hosts))
            ))
            self.sql_param += hosts
        if ports:
            self.sql.append('(`port` = ? or `port` is null)')
            self.sql_param.append(ports)
        if arguments:
            self.sql.append('`arguments` = ?')
            self.sql_param.append(arguments)

        self.sql.append('`updated_at` > ?')
        self.sql_param.append(datetime.now() - timedelta(days=days))

        self.sql = re.sub(r'\s+', ' ', '''
            SELECT
            `host`,
            `port`,
            `arguments`,
            `command_line`,
            `data`
            FROM `nmap` WHERE ''' + ' AND '.join(self.sql)
        ).replace('\n', ' ').strip()

        _db = net_db()
        _r = _db.cursor.execute(self.sql, self.sql_param).fetchall()
        _db.close()


        return _r if _r else None

    def nm_scan(self, *args, **kargs):

        self.args(args, kargs)

        self.ps.scan(
            self.hosts,
            arguments='-sn -n -PE -PA21-23,80,443,3389,5899-5949'
        )

        _ips = self.ps.all_hosts()
        _results = self.read(', '.join(_ips))
        if _results:
            _db_ips = list(map(lambda _: _[0], _results))
        else:
            _results = []
            _db_ips = []

        # check if we are running as root, if not remove options
        # that need root

        _arguments = self.arguments
        try:
            self.ps.scan('127.0.0.1', arguments='-o')
        except nm.nmap.PortScannerError:
            _arguments = self.arguments_non_root

        if _db_ips:
            _ips = list(filter(lambda _: _ not in _db_ips, _ips))
        _ips = ' '.join(_ips)
        _nm = nm.PortScannerYield()

        _db = net_db()
        for _entry in _nm.scan(_ips, self.ports, arguments=_arguments):

            _ip = _entry[0]
            _cmd = _entry[1]['nmap']['command_line']

            self.sql = re.sub(r'\s+', ' ', '''
                insert into `nmap`
                (`host`, `port`, `arguments`, `command_line`, `data`)
                values (?1, ?2, ?3, ?4, ?5)
                on conflict(`host`, `port`, `arguments`) do update set
                command_line = ?4, data = ?5
            ''').replace('\n', ' ').strip()

            self.sql_param =  (
                _ip,
                self.ports,
                _arguments,
                _cmd,
                json.dumps(_entry)
            )

            _db.cursor.execute(self.sql, self.sql_param)
            _results.append((_ip, self.ports, _arguments, _cmd, _entry))

        _db.conn.commit()
        _db.close()
        self.results = _results
        return self.results

# n = nmap()
# n.hosts = 'dc1 dc2'
# n.nm_scan()
# print(n.hosts)
# print(n.results)

# sys.exit()

class ldap():
    import ldap3

    def __init__(self):

        from configparser import RawConfigParser, NoSectionError
        _path = globals()['__CONFIG_PATH']
        _section = globals()['__CONFIG_SECTION_LDAP']
        _parser = RawConfigParser()
        self.__user, self.__domain = '', ''

        try:
            _parser.read(_path)
            self.dc = _parser.get(_section, "dc").strip()
            self.fqdn = _parser.get(_section, "fqdn").strip()
            self.domain = _parser.get(_section, "domain").strip()
            self.user = _parser.get(_section, "user").strip()
            self.password = _parser.get(_section, "password").strip()

        except NoSectionError as e:
            print(e)
            sys.exit()

        self.filt = '(objectclass=computer)'
        self.attr = ldap3.ALL_ATTRIBUTES
        self.days = 1
        self.db = net_db()
        self.error = None
        self.data = None
        self.conn = None
        self.connect()

    @property
    def fqdn(self):
        return self.__fqdn

    @fqdn.setter
    def fqdn(self, fqdn):
        self.__fqdn = fqdn
        self.base = ','.join(['dc=' + _ for _ in fqdn.split('.')])

    @property
    def domain(self):
        return self.__domain

    @domain.setter
    def domain(self, domain):
        self.__domain = domain
        self.username = domain + '\\' + self.user

    @property
    def user(self):
        return self.__user

    @user.setter
    def user(self, user):
        self.__user = user.split('\\')[0]
        self.username = self.domain + '\\' + self.__user

    def connect(self):

        try:
            self.conn = ldap3.Connection(
                server=ldap3.Server("ldap://" + self.dc),
                user=self.username,
                password=self.password,
                authentication=ldap3.NTLM,
                auto_bind=True
            )

        except(ldap3.core.exceptions.LDAPBindError,
                ldap3.core.exceptions.LDAPSocketOpenError) as e:
            self.error = e
            if not self.db:
                self.db = net_db()
                if not self.db:
                    print('no ldap or database connections. exiting..')
                    sys.exit()

    def scan(self):

        from datetime import datetime

        _db_row = self.db.cursor.execute("""
        select `data`, `updated_at` from `ldap`
        where `base` = ?  and `filter` = ?  and `attr` = ?
        and `updated_at` > ?
        order by `updated_at` desc
        """, (
            self.base,
            self.filt,
            json.dumps(self.attr),
            datetime.now() - timedelta(days=self.days)
        )).fetchone()

        if _db_row:
            self.data = json.loads(_db_row[0])
            return self.data

        if not self.conn:
            self.connect()

        if not _db_row:
            if not self.conn:
                self.connect()  # third attempt
            if not self.conn:
                print('no database and no ldap connection. exiting..')
                sys.exit()

        self.conn.search(
            search_base=self.base,
            search_scope=ldap3.subtree,
            search_filter=self.filt,
            attributes=self.attr
        )

        # beacause of a couple of datetime fields in the output
        # we have to use the ldap3 lib to convert the entry to json
        # then use json lib to bring it back to dict
        self.data = [
            json.loads(_.entry_to_json()) for _ in self.conn.entries
        ]

        if self.data:
            self.db.cursor.execute("""
            insert into `ldap`(`base`, `filter`, `attr`, `data`)
            values(?1, ?2, ?3, ?4)
            on conflict(`base`, `filter`, `attr`) do update set
            `data` = ?4
            """, [
                self.base,
                self.filt,
                json.dumps(self.attr),
                json.dumps(self.data)
            ])

            self.db.conn.commit()

        return self.data

    def close(self):
        if self.conn:
            self.conn.unbind
        if self.db.cursor:
            self.db.cursor.close
        return

def get_members ( group, objectclass = None ):
    """list all members of an ldap group.
if an objectclass is not given or is not a supported objectclass then the
distinguishedNames are listed. if a supported objectcclass is specified,
then a further query is done to determine if each member matches the
objectclass and just the cn of the matching members are listed.
supported objectclass are ('computer', 'user')
"""

    _ldap        = ldap_scan()
    _ldap.filt = '(&(objectclass=group)(name={}))'.format(group)
    _ldap.attr   = ['*']
    _data0       = _ldap.scan()

    if not (objectclass and objectclass in ( 'computer', 'user')):
        return _data0[0]['attributes']['member'] if _data0 else []

    _data = []
    if _data0:
        for _member in _data0[0]['attributes']['member']:
            _ldap.filt  = '''
            (&(objectclass={})(distinguishedName={}))
            '''.format(objectclass, _member)
            _ldap.attr    = ['*']
            _classmembers = _ldap.scan()
            for _classmember in _classmembers:
                _data.append(
                    _classmember['dn'].split(',')[0].split('=')[1]
                )

    _ldap.close()
    return _data

def get_members_computer ( group ):
    """list all computer objects that are members of the specified group"""
    return get_members (group, 'computer')


class host():

    import re

    def __init__(self):
        self.__ldap = None
        self.__nmap = None
        self.__name = None
        self.distinguishedName = None
        self.dnsHostName = None
        self.operatingSystemVersion = None
        self.operatingSystem = None
        self.os = None
        self.ostype = None
        self.version = None
        self.build = None
        self.ipv4 = None
        self.addresses = []
        self.hostnames = []
        self.osmatch = []
        self.tcp = []

    def __str__(self):
        return "{:15} {:11} {:8} {}".format(
            self.name if self.name else '',
            self.ipv4 if self.ipv4 else '',
            self.os if self.os else '',
            self.ostype if self.ostype else ''
        )

    @property
    def ldap(self):
        return self.__ldap

    @ldap.setter
    def ldap(self, ldap):
        self.__ldap = ldap
        if ldap:
            if 'name' in ldap.keys():
                self.name = ldap['name'][0]
            if 'dnsHostName' in ldap.keys():
                self.dnsHostName = ldap['dnshostname'][0]
            if 'distinguishedName' in ldap.keys():
                self.distinguishedName = ldap['distinguishedname'][0]
            if 'operatingSystem' in ldap.keys():
                self.operatingSystem = ldap['operatingsystem'][0]
            if 'operatingSystemVersion' in ldap.keys():
                self.operatingSystemVersion = ldap['operatingSystemversion'][0]

    @property
    def nmap(self):
        return self.__nmap

    @nmap.setter
    def nmap(self, nmap):
        self.__nmap = nmap
        if nmap:
            # do this before addresses
            _n = nmap[4][1]['scan'][nmap[0]]
            if 'hostnames' in _n.keys():
                self.hostnames = _n['hostnames']
            if 'addresses' in _n.keys():
                self.addresses = _n['addresses']
            if 'osmatch' in _n.keys():
                self.osmatch = _n['osmatch']
            if 'tcp' in _n.keys():
                self.tcp = _n['tcp']

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, name):
        self.__name = name

    @property
    def tcp(self):
        return self.__tcp

    @tcp.setter
    def tcp(self, tcp):
        self.__tcp = tcp
        if not self.os:
            _st = json.dumps(self.__tcp).lower()
            _wc = _st.count('windows')
            _lc = _st.count('linux')
            if _wc > _lc:
                self.os = 'windows'
            elif _lc > _wc:
                self.os = 'linux'


    @property
    def ostype(self):
        if self.__ostype:
            return self.__ostype
        _o = self.operatingSystem
        if _o:
            if 'windows' in _o.lower():
                if 'server' in _o.lower():
                    self.__ostype = 'server'
                    return self.__ostype
                else:
                    self.__ostype = 'workstation'
                    return self.__ostype
            elif 'linux' in _o.lower():
                self.__ostype = 'linux'
                return self.__ostype
        else:
            return


    @ostype.setter
    def ostype(self, ostype):
        self.__ostype = ostype

    @property
    def dnsHostName(self):
        return self.__dnsHostName

    @dnsHostName.setter
    def dnsHostName(self, dnshostname):
        self.__dnsHostName = dnshostname
        if dnsHostName and dnshostname != '':
            self.__name = dnsHostName.split('.')[0]

    @property
    def operatingSystem(self):
        if self.__operatingSystem:
            return self.__operatingSystem
        if self.__ldap and 'operatingSystem' in self.__ldap.keys():
            self.operatingSystem = self.__ldap['operatingsystem'][0]


    @operatingSystem.setter
    def operatingSystem(self, os):
        self.__operatingSystem = os
        if os:
            if 'windows' in os.lower():
                self.os = 'windows'
                if 'server' in os.lower():
                    self.ostype = 'server'
                else:
                    self.ostype = 'workstation'
            elif 'linux' in os.lower():
                self.os = 'linux'
                self.ostype = 'linux'

    @property
    def operatingSystemVersion(self):
        return self.__operatingSystemVersion

    @operatingSystemVersion.setter
    def operatingSystemVersion(self, version):
        __re_ver = re.compile('^([0-9]+).*$')
        __re_bld = re.compile('^.*\(([0-9]*)\).*$')
        self.__operatingSystemVersion = version
        if version:
            self.version = int(re.sub(__re_ver, r'\1', version))
            self.build = int(re.sub(__re_bld, r'\1', version))
        else:
            self.version, self.build = None, None

    @property
    def hasspn(self):
        return 'serviceprincipalname' in self.ldap.keys()

    @property
    def ipv4(self):
        return self.__ipv4

    @ipv4.setter
    def ipv4(self, ipv4):
        self.__ipv4 = ipv4
        if not self.name:
            self.name = ipv4

    @property
    def addresses(self):
        return self.__addresses

    @addresses.setter
    def addresses(self, addresses):
        self.__addresses = addresses
        if addresses:
            if 'ipv4' in addresses.keys():
                self.__ipv4 = addresses['ipv4']
                if not self.name:
                    self.name = self.__ipv4

    @property
    def hostnames(self):
        return self.__hostnames

    @hostnames.setter
    def hostnames(self, hostnames):
        self.__hostnames = hostnames
        if hostnames:
            _h = hostnames[0]['name'].split('.')
            _n, _d = _h[0], _h[1:]
            if _d:
                self.domain = '.'.join(_d)
            if _n:
                self.name = _n
            if _n and _d:
                self.__dnsHostName = self.name + '.' + self.domain


    @property
    def osmatch(self):
        return self.__osmatch

    @osmatch.setter
    def osmatch(self, osmatch):
        self.__osmatch = osmatch
        if osmatch:
            _osmatch = {
                'name': None,
                'cpe':None,
                'osfamily': None,
                'osgen': None
            }
            for _match in osmatch:
                if _osmatch['name'] and _osmatch['cpe'] and _osmatch['osfamily']:
                    break
                if 'name' in _match.keys():
                    _osmatch['name'] = _match['name']
                if 'osclass' in _match.keys():
                    for _osclass in _match['osclass']:
                        if _osmatch['name'] and _osmatch['cpe'] and _osmatch['osfamily']:
                            break
                        if 'cpe' in _osclass.keys():
                            _osmatch['cpe'] = _osclass['cpe']
                        if 'osfamily' in _osclass.keys():
                            _osmatch['osfamily'] = _osclass['osfamily']
                        if 'osgen' in _osclass.keys():
                            _osmatch['osgen'] = _osclass['osgen']

            if _osmatch['name']:
                self.operatingSystem = _osmatch['name']
            self.cpe = _osmatch['cpe']
            self.osfamily = _osmatch['osfamily']
            self.osgen = _osmatch['osgen']

    @property
    def cpe(self):
        return self.__cpe

    @cpe.setter
    def cpe(self, cpe):
        self.__cpe = cpe
        if not self.os:
            if 'windows' in cpe.lower():
                self.os = 'windows'
            elif 'linux' in cpe.lower():
                self.os = 'linux'

    @property
    def osfamily(self):
        return self.__osfamily

    @osfamily.setter
    def osfamily(self, osfamily):
        self.__osfamily = osfamily
        if not self.os:
            if 'windows' in osfamily.lower():
                self.os = 'windows'
            elif 'linux' in osfamily.lower():
                self.os = 'linux'

class hosts():

    def __init__(self):
        self.scan_ldap()

    @property
    def hosts(self):
        try:
            self.__hosts
        except (nameError, attributeError):
            self.__hosts = []
        return self.__hosts

    @hosts.setter
    def hosts(self, hosts):
        self.__hosts = hosts

    def append(self, hosts):

        def do(host):
            index = None
            for i, entry in enumerate(self.hosts):
                if entry.name.lower() == host.name.lower():
                    index = i
                    break
            if index:
                try:
                    self.hosts[index].ldap = host.ldap
                except (nameError, attributeError):
                    pass
                try:
                    self.hosts[index].groups = host.groups
                except (nameError, attributeError):
                    pass
                try:
                    self.hosts[index].tcp = host.tcp
                except (nameError, attributeError):
                    pass
                try:
                    self.hosts[index].nmap = host.nmap
                except (nameError, attributeError):
                    pass
            else:
                self.hosts.append(host)

        if hosts:
            try:
                self.hosts
            except (nameError, attributeError):
                self.hosts = []

            if type(hosts) is list:
                for host in hosts:
                    do(host)
            else:
                do(hosts)

    def scan_ldap(self):

        _ldap = ldap()
        _ldap.filt = '(objectclass=computer)'
        _ldap_scan = _ldap.scan()
        _nmap_results = []
        _results = []

        for _d in _ldap_scan:
            if 'objectclass' in _d['attributes'].keys() and (
                'computer' in _d['attributes']['objectclass']):
                _c = host()
                _c.ldap = _d['attributes']
                _ldap.filt = '''(&(objectclass=group)(member={}))
                '''.format(_c.distinguishedName)
                _ldap.attr = ['cn']
                _c.groups = list(map(
                    lambda _ : _['attributes']['cn'][0], _ldap.scan()
                ))
                if _c.dnsHostName and _c.os == 'windows':
                    _c.tcp = {
                        22: { 'name': 'ssh' },
                        3389: { 'name': 'ms-wbt-server' },
                        5899: { 'name': 'vnc' } }
                else:
                    _nmap_results.append(_c.name + '.' + _ldap.fqdn)

                _results.append(_c)
                self.append(_c)

        if _nmap_results:
            self.scan_nmap(_nmap_results)

    def scan_nmap(self, hosts):
        results = []
        _nmap = nmap()
        for h in _nmap.nm_scan(' '.join(hosts)):
            _host = host()
            _host.nmap = h
            results.append(_host)
            self.append(_host)
            return results




# x =  scan()
# for y in x.hosts:
#     print(str(y))

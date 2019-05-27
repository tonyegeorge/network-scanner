
import sys
import copy
import os
import re
import json
import inspect
import sqlite3
import logging
import pymysql
import nmap as nm
import ldap3
from configparser import ConfigParser, RawConfigParser, NoSectionError, NoOptionError
from pypsrp.client import Client
from pprint import pprint
from datetime import datetime, timedelta
from IPy import IP
from collections import OrderedDict
import itertools

this_file = os.path.abspath(
    inspect.getframeinfo(inspect.currentframe()).filename)
this_dir = os.path.dirname(this_file)
ports  = '22,23,42,53,67,80-88,'
ports += '135-139,389,443-445,636,'
ports += '1512,3000,3268,3269,3389,5899-5986,8080'
config = {
    'path': os.path.join(this_dir, 'net.cfg'),
    'db': {
        'type': 'sqlite',
        'init': False,
        'path': os.path.join(this_dir, "net.db"),
        'host': 'localhost',
        'port': 3306,
        'user': None,
        'password': None,
        'database': 'net_db',
        },
    'nmap': {
        'hosts': None,
        'fqdn': None,
        'ip_range': None,
        'days': 7,
        'ports': ports,
        # 'arguments': '-O -Pn -R -sV',
        'arguments': '-O -sC -sV -T4',
        'arguments_needing_root': '-O -sS',
        'arguments_ping_scan': '-sn -n',
        },
    'ldap': {
        'days': 3,
        'fqdn': None,
        'domain': None,
        'dc': None,
        'user': None,
        'password': None,
        'key_file': None,
        },
    'mysql': {
        'host': 'localhost',
        'port': 3306,
        'user': None,
        'passwd': None,
        'db': None,
    },
    'log': {
        'file': os.path.split(this_file)[0] + '.log',
        'level': logging.DEBUG,
        'format': "%(asctime)s: %(levelname)s: %(message)s",
        }
    }

def mergeConf(dict1, dict2):
    for k1,v1 in dict2.items():
        for k2,v2 in v1.items():
            if v2 is not None:
                if k1 in dict1.keys():
                    dict1[k1][k2] = v2
                else:
                    dict1[k1] = {k2:v2}

parser = ConfigParser()
parser.read(config['path'])
mergeConf(config, {
    k: dict(parser.items(k))
    for k in parser.sections()
})

# pprint(config)
class db():
    """sqlite database for storing network data collected by nmap
    and ldap queries
    """
    def __init__(self,
        _type=globals()['config']['db']['type'],
        init=globals()['config']['db']['init'],
        path=globals()['config']['db']['path'],
        host=globals()['config']['db']['host'],
        port=globals()['config']['db']['port'],
        user=globals()['config']['db']['user'],
        password=globals()['config']['db']['password'],
        database=globals()['config']['db']['database'],
        config_file=None,
        config=globals()['config'],
    ):

        self.conf = copy.deepcopy(config)

        if config_file and os.path.isfile(config_file):
            parser.read(config_file)
            mergeConf(self.conf,{
                k: dict(parser.items(k))
                for k in parser.sections()
            })

        mergeConf(self.conf, {
            'db': {
                'type': _type,
                'init': init,
                'path': path,
                'host': host,
                'port': port,
                'user': user,
                'password': password,
                'database': database,
                },
            })

        self._type = self.conf['db']['type']

        if self._type == 'mysql':

            self.host = self.conf['db']['host']
            self.port = self.conf['db']['port']
            self.user = self.conf['db']['user']
            self.password = self.conf['db']['password']
            self.database = self.conf['db']['database']

            try:

                self.conn = pymysql.connect(
                    host=self.host,
                    user=self.user,
                    passwd=self.password,
                    db=self.database,
                    port=int(self.port))

            except:

                print('mysql connection error')
                self.conn = None
                sys.exit()

        else:

            self.init = self.conf['db']['init']
            self.path = self.conf['db']['path']

            try:

                self.conn = sqlite3.connect(
                    self.path,
                    detect_types=sqlite3.PARSE_DECLTYPES
                )

            except:

                print('sqlite connection error')
                self.conn = None
                sys.exit()


        self.cursor = self.conn.cursor()
        self.data = None

        if self.init is True:
            self.drop_tables()

        self.create_tables()

        if self._type == 'sqlite':
            with self.conn:
                self.cursor.execute('PRAGMA journal_mode=wal')

    def columns(self, table=None, show=False):
        if not table:
            return self.tables(True, show)
        else:
            if not isinstance(table, str):
                return

        self.cursor.execute('SELECT * FROM {} LIMIT 1'.format(table))
        __results = list(map(
            lambda x: x[0], self.cursor.description
        ))
        if show is True:
            print(table)
            print('-' * len(table))
            for __result in __results:
                print (__result)
        return(__results)

    def tables(self, columns=False, show=False):

        if self._type == 'postgres':
            __sql = '''
                SELECT * FROM pg_catalog.pg_tables
                WHERE schemaname != 'pg_catalog'
                AND schemaname != 'information_schema'
                '''
        elif self._type == 'mysql':
            __sql = 'SHOW TABLES'
        else:
            __sql = "SELECT name FROM sqlite_master WHERE type='table'"

        self.cursor.execute(__sql)
        __results = self.cursor.fetchall()
        if columns is True:
            __results = list(map(
                lambda x: (x[0], self.columns(x[0])),
                __results
            ))
            if show is True:
                print('tables')
                print('======')
                for __table in results:
                    print(__table[0])
                    print('-' * len(__table[0]))
                    for __column in __table[1]:
                        print(__column)
        else:
            __results = list(map( lambda x: x[0], __results))
            if show is True:
                print('tables')
                print('======')
                for __table in __results:
                    print(__table)
        return __results

    def create_tables(self):

        with self.conn:
            self.conn.cursor().executescript(
                re.sub(r'\n\s*', '\n', '''
                CREATE TABLE IF NOT EXISTS `nmap`(
                `host` VARCHAR(20),
                `ports` TEXT,
                `arguments` TEXT,
                `command_line` TEXT,
                `data` JSON,
                `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(`host`, `ports`, `arguments`)
                );
                CREATE TABLE IF NOT EXISTS `ldap`(
                `search_base` TEXT NOT NULL,
                `search_filter` TEXT NOT NULL,
                `attributes` JSON,
                `data` JSON,
                `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(`search_base`, `search_filter`, `attributes`)
                );
                ''')
            )

        # add a trigger for each table to update the
        # modified timestamp
        __sql = ''
        for __table in self.tables(True):
            __sql += '''
            DROP TRIGGER IF EXISTS `{0}_updated_at` ;
            CREATE TRIGGER `{0}_updated_at`
            AFTER UPDATE OF {1} ON {0}
            FOR EACH ROW
            BEGIN
            UPDATE `{0}` SET `updated_at` = CURRENT_TIMESTAMP;
            END;
            '''.format(__table[0], ',\n'.join(
                list(map(
                    lambda x: '`{}`'.format(x),
                    list(filter(
                        lambda x: x != 'updated_at', __table[1]
                    ))
                ))
            ))
        self.conn.cursor().executescript(re.sub(r'\n\s*', '\n', __sql))
        self.conn.commit()
        return


    def get_nmap(self,
        hosts=globals()['config']['nmap']['hosts'],
        ports=globals()['config']['nmap']['ports'],
        arguments=globals()['config']['nmap']['arguments'],
        days=globals()['config']['nmap']['days'],
        show=False):

        sql, self.params = [], []

        if hosts:
            if isinstance(hosts, list):
                hosts = ' '.join(hosts)
            if isinstance(hosts, str):
                hosts = re.sub(r'[\s,]+', ' ', hosts).strip().split()
                self.params += hosts
                sql.append('`host` IN ({})'.format(', '.join(['?'] * len(hosts))))

        if ports:
            if isinstance(ports, list):
                ports = ','.join(ports)
            if isinstance(ports, str):
                self.params.append(','.join(
                    ['-'.join(x) for x in sorted([re.split(
                    r'\s*-\s*', x) for x in re.sub(
                    r'[\s,]+', ' ', ports).strip().split()])]))
                sql.append('`ports`=?')

        if arguments:
            if isinstance(arguments, list):
                arguments = ' '.join(
                    [re.sub(r'^\s*-', '', x) for x in arguments])
            if isinstance(arguments, str):
                self.params.append(' '.join(['-'+x for x in sorted(re.sub(
                    r'[\s-]+', ' ', arguments).strip().split())]))
                sql.append('`arguments`=?')


        if days:
            sql.append('`updated_at`>?')
            self.params.append(datetime.now() - timedelta(days=days))

        sql = ' WHERE ' + ' AND '.join(sql) if sql else ''

        self.sql = 'SELECT `host`, `ports`, `arguments`, `command_line`, `data` FROM `nmap`'
        self.sql += sql
        self.sql += ' ORDER BY `host`, `updated_at` DESC'

        self.cursor.execute(self.sql, self.params)
        self.results = self.cursor.fetchall()
        self.results = list(map(
            lambda x: [x[0], x[1], x[2], x[3], tuple(json.loads(x[4]))],
            self.results
        ))

        # if show is True:
        #     fmt = '{0:15} {1:25} {2:12} {3}'
        #     print(fmt.format('host', 'ports', 'argumemnts', 'command_line'))
        #     print(fmt.format('----', '-----', '----------', '------------'))
        #     for h, p, a, c, d in self.results:
        #         print(fmt.format(h, p, a, c))
        # self.results = list(map(
        #     lambda x: (x[0], x[1], x[2], x[3]),
        #     self.results
        # ))
        return self.results

    def set_nmap(self,
        host=None,
        ports=None,
        arguments=None,
        command_line=None,
        data=None):

        if host:
            host = host.strip().lower()

        if ports:
            if isinstance(ports, list):
                ports = ','.join(ports)
            if isinstance(ports, str):
                ports = ','.join(
                    ['-'.join(x) for x in sorted([re.split(
                    r'\s*-\s*', x) for x in re.sub(
                    r'[\s,]+', ' ', ports).strip().split()])])

        if arguments:
            if isinstance(arguments, list):
                arguments = ' '.join(
                    [re.sub(r'^\s*-', '', x) for x in arguments])
            if isinstance(arguments, str):
                arguments = ' '.join(['-'+x for x in sorted(re.sub(
                    r'[\s-]+', ' ', arguments).strip().split())])

        if host and data:
            self.sql = re.sub(r'\s+', ' ', '''
                INSERT INTO `nmap`
                (`host`, `ports`, `arguments`, `command_line`, `data`)
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(`host`, `ports`, `arguments`) DO UPDATE SET
                command_line = ?4, data = ?5
            ''').replace('\n', ' ').strip()
            self.params =  (
                host,
                ports,
                arguments,
                command_line,
                json.dumps(data)
            )
            self.conn.cursor().execute(self.sql, self.params)
            self.conn.commit()

    def get_ldap(self,
        search_base=None,
        search_filter=None,
        attributes=None,
        days=None,
        show=False):

        self.sql = []
        self.params = []

        if search_base:
            self.sql.append('`search_base` = ?')
            self.params.append(search_base)

        if search_filter:
            self.sql.append('`search_filter` = ?')
            self.params.append(search_filter)

        if attributes:
            self.sql.append('`attributes` = ?')
            self.params.append(json.dumps(attributes))

        if days:
            self.sql.append('`updated_at` > ?')
            self.params.append(datetime.now() - timedelta(days=days))

        if self.sql:
            self.sql = ' WHERE' + ' AND '.join(self.sql)
        else:
            self.sql = ''

        self.sql = re.sub(r'\s+', ' ', re.sub(
            r'\n\s*', ' ', '''
            SELECT
            `search_base`,
            `search_filter`,
            `attributes`,
            `data`
            FROM `ldap`
            ''' + self.sql + '''
            ORDER BY `search_base`, `updated_at` DESC
            '''
        )).strip()

        self.results = []
        with self.conn:
            __cursor = self.conn.cursor()
            __cursor.execute(self.sql, self.params)
            self.results = __cursor.fetchall()
        if show is True:
            fmt = '{0:30.30} {1:30.30} {2:10.10} {3:40.40}'
            print(fmt.format(
                'search_base', 'search_filter', 'attributes', 'data'
            ))
            print(fmt.format(
                '-' * 30, '-' *30, '-' * 10, '-' * 40
            ))
            for b, f, a, d in self.results:
                print(fmt.format(b, f, a, d))

        self.results = list(map(
            lambda x: (x[0], x[1], json.loads(x[2]), json.loads(x[3])),
            self.results
        ))
        return self.results

    def set_ldap(self,
        search_base=None,
        search_filter=None,
        attributes=None,
        data=None):
        if (search_base or search_filter or attributes) and data:

            self.sql = re.sub(r'\s+', ' ', '''
                INSERT INTO `ldap` (
                `search_base`,
                `search_filter`,
                `attributes`,
                `data`)
                VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(
                `search_base`,
                `search_filter`,
                `attributes`) DO UPDATE SET
                `data` = ?4
            ''').replace('\n', ' ').strip()

            self.params =  (
                search_base,
                search_filter,
                json.dumps(attributes),
                json.dumps(data)
            )

            self.cursor.execute(self.sql, self.params)
            self.conn.commit()

    def drop_tables(self):
        for table in self.tables():
            self.sql = 'drop table if exists {}'.format(table)
            self.cursor.execute(self.sql)

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

    def close(self):
        self.cursor.close()
        self.conn.close()

# DB = db()

class mysql:

    def __init__(self, **kargs):

        def do(k, a, d):
            if a in k.keys():
                return k[a]
            else:
                return d

        self.host = do(kargs, 'host', globals()['config']['mysql']['host'])
        self.port = do(kargs, 'port', globals()['config']['mysql']['port'])
        self.user = do(kargs, 'user', globals()['config']['mysql']['user'])
        self.passwd = do(kargs, 'passwd', globals()['config']['mysql']['passwd'])
        self.db = do(kargs, 'db', globals()['config']['mysql']['db'])
        self.connect()


    def connect(self, **kargs):

        if 'host' in kargs.keys():
            self.host = kargs['host']
        if 'port' in kargs.keys():
            self.port = kargs['port']
        if 'user' in kargs.keys():
            self.user = kargs['user']
        if 'passwd' in kargs.keys():
            self.passwd = kargs['passwd']
        if 'db' in kargs.keys():
            self.db = kargs['db']

        # try:
        self.conn = pymysql.connect(
            host=self.host,
            user=self.user,
            passwd=self.passwd,
            db=self.db,
            port=int(self.port))
        # except :
        #     # self.error = e
        #     self.connection = None
        #     sys.exit()

        self.cursor = self.conn.cursor()

    def columns(self, table):
        self.sql = "SELECT * FROM {} LIMIT 1".format(table)
        self.cursor.execute(self.sql)
        return list(map(
            lambda x: x[0], self.cursor.description
        ))

    def tables(self, columns=False):
        self.sql = "SHOW TABLES"
        self.cursor.execute(self.sql)
        self.results = self.cursor.fetchall()
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


# pprint(config)
# sys.exit()
class nmap():
    '''
    wrapper providing default values from python nmap
    fqdn, ip_range are read from the config file if not specified
    on initialization
    '''
    def __init__(self,
            db_path=globals()['config']['db']['path'],
            db_init=globals()['config']['db']['init'],
            fqdn=globals()['config']['nmap']['fqdn'],
            ip_range=globals()['config']['nmap']['ip_range'],
            ports=globals()['config']['nmap']['ports'],
            arguments=globals()['config']['nmap']['arguments'],
            days=globals()['config']['nmap']['days'],
            arguments_needing_root=globals()['config']['nmap']['arguments_needing_root'],
            arguments_ping_scan=globals()['config']['nmap']['arguments_ping_scan'],
            db=None,
            config_file=None,
            config=globals()['config'],
        ):

        self.conf = copy.deepcopy(config)

        if config_file and os.path.isfile(config_file):
            parser.read(config_file)
            mergeConf(self.conf, {
                k: dict(parser.items(k))
                for k in parser.sections()
            })

        mergeConf(self.conf, {
            'db': {
                'path': db_path,
                'init': db_init,
                },
            'nmap': {
                'fqdn': fqdn,
                'ip_range': ip_range,
                'ports': ports,
                'arguments': arguments,
                'days': days,
                'arguments_needing_root': arguments_needing_root,
                'arguments_ping_scan': arguments_ping_scan,
                },
            })

        if db:
            self.db = db
        else:
            self.db = db(self.conf['db']['path'])

        self.fqdn = self.conf['nmap']['fqdn']
        self.ip_range = self.conf['nmap']['ip_range']
        self.hosts = self.ip_range
        self.ports = self.conf['nmap']['ports']
        self.arguments = self.conf['nmap']['arguments']
        self.days = self.conf['nmap']['days']
        self.nm = nm
        self.arguments_non_root = ' '.join(list(filter(
            lambda x: x not in
                self.conf['nmap']['arguments_needing_root'].split(),
            self.arguments.split()
        )))

    def scan(self,
            hosts=None,
            ports=None,
            arguments=None,
            days=None
        ):
        if hosts:
            self.hosts = hosts
        if ports:
            self.ports = ports
        if arguments:
            self.arguments = arguments
        if days:
            self.days = days
        __nm = self.nm.PortScanner()
        __nm.scan(self.hosts, arguments=self.conf['nmap']['arguments_ping_scan'])

        __results = []
        __ip_list_db = []
        __ip_list = __nm.all_hosts()
        __results = self.db.get_nmap(hosts=__ip_list)
        __ip_list_db = [_[0] for _ in  __results]

        # check if we are running as root, if not remove options
        # that need root

        # __arguments = self.arguments
        # try:
        #     __nm.scan('127.0.0.1', arguments='-O')
        # except nm.nmap.PortScannerError:
        #     __arguments = self.arguments_non_root

        if __ip_list_db:
            for __i in __results:
                print('read   : {}'.format(__i[3]))
            __ip_list = [_ for _ in __ip_list if _ not in __ip_list_db]

        __ip_list = ' '.join(__ip_list)

        if __ip_list:
            __nm = self.nm.PortScannerYield()
            # def callback_result(host, scan_result):
            #     cmd_line = scan_result['nmap']['command_line']
            #     self.db.set_nmap(
            #         host=host,
            #         ports=self.ports,
            #         arguments=self.arguments,
            #         command_line=cmd_line,
            #         data=scan_result,
            #     )
            #     print('saved {}'.format(cmd_line))
            #     __results.append((
            #         host,
            #         self.ports,
            #         self.arguments,
            #         cmd_line,
            #         scan_result,
            #     ))
            #    # pprint(scan_result)

            # print('scaning nmap -oX - -p {} {} {}'.format(
            #     self.ports, self.arguments, __ip_list), end='')
            # __nm.scan(
            #     hosts=__ip_list,
            #     ports=self.ports,
            #     arguments=self.arguments,
            #     sudo=True,
            #     callback=callback_result,
            # )
            # while __nm.still_scanning():
            #     print(".", end="")
            #     __nm.wait(2)
            # print('')

            # sys.exit()


            print('scaning: nmap -oX - -p {} {} {}'.format(
                self.ports, self.arguments, __ip_list))

            for __entry in __nm.scan(
                hosts=__ip_list,
                ports=self.ports,
                arguments=self.arguments,
                sudo=True,
            ):
                __ip = __entry[0]
                __cmd = __entry[1]['nmap']['command_line']
                self.db.set_nmap(
                    host=__ip,
                    ports=self.ports,
                    arguments=self.arguments,
                    command_line=__cmd,
                    data=__entry
                )
                print('saved  : {}'.format(__cmd))
                __results.append((
                    __ip,
                    self.ports,
                    self.arguments,
                    __cmd,
                    __entry
                ))

        self.results = __results
        # pprint(self.results)
        return self.results

    @property
    def hosts(self):
        return self.__hosts

    @hosts.setter
    def hosts(self, hosts=''):
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

        if hosts and hosts != '':
            __hosts = list(map(
                lambda _: fix(_), list(filter(
                    lambda x: x, re.split(r'\s*,?\s+|\s+,?\s*', hosts)
            ))))
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
        if arguments:
            def l(a):
                if a:
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
            __args_root = l(self.conf['nmap']['arguments_needing_root'])
            __args_non_root = list(
                filter(lambda _: _ not in __args_root, __args)
            )
            self.__arguments = ' '.join(list(
                map(lambda _: '-' + str(_), __args)
            ))
            self.arguments_non_root = ' '.join(list(
                map(lambda _: '-' + str(_), __args_non_root)
            ))
        else:
            self.__arguments = None

    @property
    def days(self):
        return self.__days

    @days.setter
    def days(self, days):
        self.__days = days

class ldap():

    def __init__(self,
            db_path=globals()['config']['db']['path'],
            db_init=globals()['config']['db']['init'],
            fqdn=globals()['config']['ldap']['fqdn'],
            domain=globals()['config']['ldap']['domain'],
            dc=globals()['config']['ldap']['dc'],
            user=globals()['config']['ldap']['user'],
            password=globals()['config']['ldap']['password'],
            days=globals()['config']['ldap']['days'],
            key_file=globals()['config']['ldap']['key_file'],
            db=None,
            config_file=None,
            config=globals()['config'],
        ):

        self.conf = copy.deepcopy(config)

        if config_file and os.path.isfile(config_file):
            parser.read(config_file)
            mergeConf(self.conf, {
                k: dict(parser.items(k))
                for k in parser.sections()
            })

        mergeConf(self.conf, {
            'db': {
                'path': db_path,
                'init': db_init,
                },
            'ldap': {
                'fqdn': fqdn,
                'domain': domain,
                'dc': dc,
                'user': user,
                'password': password,
                'days': days,
                'key_file': key_file,
                },
            })

        if db:
            self.db = db
        else:
            self.db = db(self.conf['db']['path'])
        self.dc = self.conf['ldap']['dc']
        self.fqdn = self.conf['ldap']['fqdn']
        self.domain = self.conf['ldap']['domain']
        self.user = self.conf['ldap']['user']
        self.password = self.conf['ldap']['password']
        # self.key_file = self.conf['ldap']['key_file']
        self.days = self.conf['ldap']['days']
        self.ldap = ldap3
        self.search_filter = '(objectclass=computer)'
        self.attributes = ldap3.ALL_ATTRIBUTES
        self.search_scope = ldap3.SUBTREE
        self.connection()

    @property
    def fqdn(self):
        return self.__fqdn

    @fqdn.setter
    def fqdn(self, fqdn):
        self.__fqdn = fqdn
        if fqdn and fqdn != '':
            self.search_base = ','.join(['dc=' + _ for _ in fqdn.split('.')])

    @property
    def domain(self):
        return self.__domain

    @domain.setter
    def domain(self, domain):
        self.__domain = domain
        try:
            self.__user
            self.username = domain + '\\' + self.user
        except:
            pass

    @property
    def user(self):
        try:
            self.__user
            return self.__user
        except:
            pass


    @user.setter
    def user(self, user):
        self.__user = user.split('\\')[0]
        self.__username = self.domain + '\\' + self.__user

    @property
    def username(self):
        return self.__username

    @username.setter
    def username(self, username):
        __username = username.split('\\')
        if len(__username) > 1:
            self.__username = __username[0] + '\\' + __username[1]
        else:
            self.__username = self.domain + '\\' + __username[0]

    def connection(self, **kargs):

        def do():
            def x(var, idx, val=None):
                if idx in var.keys():
                    return var[idx]
                else:
                    if val:
                        return val
            return (
                x(kargs, 'dc', self.dc),
                x(kargs, 'user', self.username),
                x(kargs, 'password', self.password),
                x(kargs, 'authentication', ldap3.NTLM),
                x(kargs, 'auto_bind', True)
            )

        (
            self.dc,
            self.username,
            self.password,
            self.authentication,
            self.auto_bind
        ) = do()

        try:
            self.conn = ldap3.Connection(
                server='ldap://' + self.dc,
                user=self.username,
                password=self.password,
                authentication=self.authentication,
                auto_bind=self.auto_bind
            )

        except(ldap3.core.exceptions.LDAPBindError,
                ldap3.core.exceptions.LDAPSocketOpenError) as e:
            self.error = e
            sys.exit()

    def search(self,
            search_base=None,
            search_scope=None,
            search_filter=None,
            attributes=None,
            days=None
        ):

        if search_base: self.search_base = search_base
        if search_scope: self.search_scope = search_scope
        if search_filter: self.search_filter = search_filter
        if attributes: self.attributes = attributes
        if days: self.days = days

        self.data = self.db.get_ldap(
            search_base=self.search_base,
            search_filter=self.search_filter,
            attributes=self.attributes,
            days=self.days
        )
        if self.data:
            # print(self.data[0][1])
            self.data = self.data[0][3]
            print('read   : ldap {}'.format(self.search_filter))
            return self.data

        self.conn.search(
            search_base=self.search_base,
            search_scope=self.search_scope,
            search_filter=self.search_filter,
            attributes=self.attributes
        )

        # beacause of a couple of datetime fields in the output
        # we have to use the ldap3 lib to convert the entry to json
        # then use json lib to bring it back to dict
        self.data = list(map(
            lambda x: json.loads(x.entry_to_json()), self.conn.entries
        ))
        # print(self.search_filter)
        self.db.set_ldap(
            search_base=self.search_base,
            search_filter=self.search_filter,
            attributes=self.attributes,
            data=self.data
        )
        print('saved  : ldap {}'.format(self.search_filter))
        return self.data

    def close(self):
        if self.conn:
            self.conn.unbind
        if self.db.cursor:
            self.db.cursor.close
        return

class host():

    def __init__(self):

        self.__build = None
        self.__dNSDomainName = None
        self.__dNSHostName = None
        self.__dNSHostNames = []
        self.__groups = []
        self.__ipv4 = None
        self.__ldap = {}
        self.__name = None
        self.__names = []
        self.__nmap = {}
        self.__operatingSystem = None
        self.__operatingSystemVersion = None
        self.__osFamily = None
        self.__osType = None
        self.__osVersion = None
        self.__tcp = {}

    @property
    def build(self):
        return self.__build

    @build.setter
    def build(self, val):
        self.__build = val

    @property
    def dNSDomainName(self):
        return self.__dNSDomainName

    @dNSDomainName.setter
    def dNSDomainName(self, val):
        self.__dNSDomainName = val.lower()

    @property
    def dNSHostName(self):
        return self.__dNSHostName

    @dNSHostName.setter
    def dNSHostName(self, val):
        self.__dNSHostName = val.lower()

    @property
    def dNSHostNames(self):
        return self.__dNSHostNames

    @dNSHostNames.setter
    def dNSHostNames(self, val):
        self.__dNSHostNames = val

    @property
    def groups(self):
        return self.__groups

    @groups.setter
    def groups(self, val):
        self.__groups = val

    @property
    def ipv4(self):
        return self.__ipv4

    @ipv4.setter
    def ipv4(self, val):
        self.__ipv4 = val

    @property
    def ldap(self):
        return self.__ldap

    @ldap.setter
    def ldap(self, val):
        self.__ldap = val
        if 'dNSHostName' in self.__ldap.keys() and self.__ldap['dNSHostName'] and not self.dNSHostName:
            self.dNSHostName = self.__ldap['dNSHostName'][0]
        if 'operatingSystem' in self.__ldap.keys() and self.__ldap['operatingSystem']:
            self.operatingSystem = self.__ldap['operatingSystem'][0]
        if 'operatingSystemVersion' in self.__ldap.keys() and self.__ldap['operatingSystemVersion']:
            self.operatingSystemVersion = self.__ldap['operatingSystemVersion'][0]
        if self.dNSHostName and self.osFamily == 'windows':
            self.tcp = {
                22: { 'name': 'ssh' },
                3389: { 'name': 'ms-wbt-server' },
                5899: { 'name': 'vnc' }}
        if self.dNSHostName and self.osFamily == 'linux':
            self.tcp = {22: { 'name': 'ssh' }}

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, val):
        self.__name = val.lower()

    @property
    def names(self):
        return self.__names

    @names.setter
    def names(self, val):
        self.__names = val

    @property
    def nmap(self):
        return self.__nmap

    @nmap.setter
    def nmap(self, val):
        self.__nmap = val
        # pprint(val)
        # wait = input("PRESS ENTER TO CONTINUE.")
        if not self.__nmap[1]['scan']:
            return

        _nm = self.__nmap[1]['scan'][self.__nmap[0]]

        if 'hostnames' in _nm.keys():
            _hn = [x['name'].lower() for x in _nm['hostnames']]
            _hh = [x for x in _hn if len(x.split('.')) == 1]
            _hd = [x for x in _hn if len(x.split('.')) > 1]
            self.names = list(set(self.names).union(set(_hh)))
            self.dNSHostNames = list(set(self.dNSHostNames).union(set(_hd)))

        if 'tcp' in _nm.keys():
            self.tcp = _nm['tcp']

        if not (self.operatingSystem and self.osFamily and self.osVersion and self.name and self.dNSDomainName and self.dNSHostName):

            if 'hostscript' in _nm.keys() and len(_nm['hostscript']) > 0:
                _hs = [x for x in _nm['hostscript'] if x['id'] == 'smb-os-discovery']
                if len(_hs) > 0 and 'output' in _hs[0].keys():
                    _hs = _hs[0]['output'].split('\n')
                    _hs = [x.split(':') for x in _hs if x]
                    _hs = {x[0].strip(): x[1].strip() for x in _hs}
                    if 'OS' in _hs.keys() and not self.operatingSystem:
                        self.operatingSystem = _hs['OS']
                    if 'Computer name' in _hs.keys() and not self.name:
                        self.name = _hs['Computer name']
                    if 'Domain name' in _hs.keys() and not self.dNSDomainName:
                        self.dNSDomainName = _hs['Domain name']
                    if 'FQDN' in _hs.keys() and not self.dNSHostName:
                        self.dNSHostName = _hs['FQDN']

        if not (self.operatingSystem and self.osFamily and self.osVersion):

            if 'osmatch' in _nm.keys() and len(_nm['osmatch']) > 0:
                if not self.operatingSystem:
                    self.operatingSystem = _nm['osmatch'][0]['name']
                if 'osclass' in _nm['osmatch'][0].keys():
                    if len(_nm['osmatch'][0]['osclass']) > 0:
                        x = _nm['osmatch'][0]['osclass'][0]
                        if 'osfamily' in x.keys() and not self.osFamily:
                            self.osFamily = x['osfamily'].lower()
                        if 'osgen' in x.keys() and not self.osVersion:
                            self.osVersion = x['osgen']

        if not self.osFamily:

            _vs = json.dumps(_nm).lower()
            _cw = _vs.count('windows')
            _cl = _vs.count('linux')

            if _cw > _cl:
                self.osFamily = 'windows'
            elif _cl > _cw:
                self.osFamily = 'linux'

            if not self.name and self.names:
                self.name = self.names[0]

    @property
    def operatingSystem(self):
        return self.__operatingSystem

    @operatingSystem.setter
    def operatingSystem(self, operatingSystem):
        self.__operatingSystem = operatingSystem
        if operatingSystem:
            if 'windows' in operatingSystem.lower():
                self.osFamily = 'windows'
                if 'server' in operatingSystem.lower():
                    self.osType = 'server'
                else:
                    self.osType = 'workstation'
            elif 'linux' in operatingSystem.lower():
                self.osFamily = 'linux'
                self.osType = 'linux'

    @property
    def operatingSystemVersion(self):
        return self.__operatingSystemVersion

    @operatingSystemVersion.setter
    def operatingSystemVersion(self, ver):
        self.__operatingSystemVersion = ver
        if ver:
            self.version = int(re.sub(r'^([0-9]+).*$', r'\1', ver))
            self.build = int(re.sub(r'^.*\(([0-9]*)\).*$', r'\1', ver))

    @property
    def osFamily(self):
        return self.__osFamily

    @osFamily.setter
    def osFamily(self, val):
        self.__osFamily = val.lower()

    @property
    def osType(self):
        return self.__osType

    @osType.setter
    def osType(self, val):
        self.__osType = val.lower()

    @property
    def osVersion(self):
        return self.__osVersion

    @osVersion.setter
    def osVersion(self, val):
        if self.osFamily == 'windows':
            try:
                x = float(val)
            except:
                if 'xp' in val.lower():
                    self.__osVersion = 5.2
                elif 'vista' in val.lower():
                    self.__osVersion = 6.0
                else:
                    self.__osVersion = val
            else:
                if x == 2003:
                    self.__osVersion = 5.2
                elif x == 2003:
                    self.__osVersion = 5.2
                elif x == 7 or x == 2008:
                    self.__osVersion = 6.1
                elif x == 8:
                    self.__osVersion = 6.2
                elif x == 2012:
                    self.__osVersion = 6.3
                else:
                    self.__osVersion = val
        else:
            self.__osVersion = val


    @property
    def tcp(self):
        return self.__tcp

    @tcp.setter
    def tcp(self, val):
        mergeConf(self.__tcp, val)


def dns_scan(
    server=config['ldap']['dc'],
    username='{}\\{}'.format(config['ldap']['domain'], config['ldap']['user']),
    password=config['ldap']['password'],
    ):

    dns_client = Client(server, username=username, password=password, ssl=False)
    stdout, stderr, rc = dns_client.execute_ps('''
    Get-DnsServerZone | Select-Object -Property ZoneName
    ''')
    res = {
        x: {} for x in re.split(r'[\n\s]+', stdout)
        if len(x.split('.')) > 1 and not re.search(r'\.arpa$', x)
    }
    for key in res.keys():
        stdout, stderr, rc = dns_client.execute_ps('''
        Get-DnsServerZone -Name %s |
        Get-DnsServerResourceRecord |
        where {$_.RecordType -eq "A"} |
        Select-Object -Property HostName -ExpandProperty RecordData
        ''' % (key,))
        res[key] = [x for x in [
            x.split() for x in iter(stdout.splitlines())
        ][3:] if x and x[0] != '@']
    res = {k: v for k,v in res.items() if v}
    result = []
    for d in res.keys():
        result += [{
            'dNSDomainName': d.lower(),
            'dNSHostName': sorted(x[1])[0].lower() + '.' + d.lower(),
            'dNSHostNames': [y.lower() + '.' + d.lower() for y in sorted(x[1])],
            'ipv4': x[0],
            'name': sorted(x[1])[0].lower(),
            'names': sorted(x[1]),
            } for x in [(k,[x[0]
                for x in list(v)])
                for k,v in itertools.groupby(
                sorted(res[d]),
                lambda x: x[1])]
            ]

    return result

class hosts(dict):

    def __init__(self,
            db_path=globals()['config']['db']['path'],
            db_init=globals()['config']['db']['init'],
            nmap_fqdn=globals()['config']['nmap']['fqdn'],
            nmap_ip_range=globals()['config']['nmap']['ip_range'],
            nmap_ports=globals()['config']['nmap']['ports'],
            nmap_arguments=globals()['config']['nmap']['arguments'],
            nmap_days=globals()['config']['nmap']['days'],
            nmap_arguments_needing_root=globals()['config']['nmap']['arguments_needing_root'],
            nmap_arguments_ping_scan=globals()['config']['nmap']['arguments_ping_scan'],
            ldap_fqdn=globals()['config']['ldap']['fqdn'],
            ldap_domain=globals()['config']['ldap']['domain'],
            ldap_dc=globals()['config']['ldap']['dc'],
            ldap_user=globals()['config']['ldap']['user'],
            ldap_password=globals()['config']['ldap']['password'],
            ldap_days=globals()['config']['ldap']['days'],
            ldap_key_file=globals()['config']['ldap']['key_file'],
            db=None,
            config_file=None,
            config=globals()['config'],
        ):

        self.conf = copy.deepcopy(config)

        if config_file and os.path.isfile(config_file):
            parser.read(config_file)
            mergeConf(self.conf, {
                k: dict(parser.items(k))
                for k in parser.sections()
            })

        mergeConf(self.conf, {
            'db': {
                'path': db_path,
                'init': db_init,
                },
            'nmap': {
                'fqdn': nmap_fqdn,
                'ip_range': nmap_ip_range,
                'ports': nmap_ports,
                'arguments': nmap_arguments,
                'days': nmap_days,
                'arguments_needing_root': nmap_arguments_needing_root,
                'arguments_ping_scan': nmap_arguments_ping_scan,
                },
            'ldap': {
                'fqdn': ldap_fqdn,
                'domain': ldap_domain,
                'dc': ldap_dc,
                'user': ldap_user,
                'password': ldap_password,
                'days': ldap_days,
                'key_file': ldap_key_file,
                },
            })

        if db:
            self.db = db
        else:
            self.db = db(
                path=self.conf['db']['path'],
                init=self.conf['db']['init'],
            )

        self.nm = nmap(config=self.conf, db=self.db)
        self.ld = ldap(config=self.conf, db=self.db)

    def dns_search(self):

        print('dns search ....')

        for x in dns_scan():
            if x['name'] not in self.keys():
               self[x['name']] = host()
            self[x['name']].dNSDomainName = x['dNSDomainName']
            self[x['name']].dNSHostName = x['dNSHostName']
            self[x['name']].dNSHostNames = x['dNSHostNames']
            self[x['name']].ipv4 = x['ipv4']
            self[x['name']].name = x['name']
            self[x['name']].names = x['names']

        print('dns search done')

    def ldap_search(self):

        print('ldap search ....')

        groups = self.ld.search(search_filter='(objectClass=group)', attributes=['name', 'member'])
        groups = [[x['attributes']['name'][0], x['attributes']['member'],] for x in groups]
        search = self.ld.search(search_filter='(objectClass=computer)', attributes=['*'])

        for s in search:
            if 'objectClass' in s['attributes'].keys() and ('computer' in s['attributes']['objectClass']):
                n = s['attributes']['name'][0].lower()
                if n not in self.keys():
                    self[n] = host()
                self[n].ldap = s['attributes']
                self[n].groups = [x[0] for x in groups if s['attributes']['distinguishedName'][0] in x[1]]

        print('ldap search done')

    def nmap_scan(self):

        print('nmap scan ....')

        _hosts = [v.ipv4 if v.ipv4 else v.dNSHostName for k,v in self.items()]
        _hosts = sorted([tuple(x.split('.')) for x in _hosts])
        _hosts = ' '.join(['.'.join(x) for x in _hosts])
        _ports = self.conf['nmap']['ports']
        _arguments = self.conf['nmap']['arguments']
        _days = self.conf['nmap']['days']

        def do_entry(_host, _result):
            if not _result['scan']:
                return
            _cmd = _result['nmap']['command_line']
            self.db.set_nmap(
                host=_host, ports=_ports, arguments=_arguments,
                command_line=_cmd, data=[_host, _result])
            print('\nsaved  : {}'.format(_cmd))
            _name = [x for x,y in self.items() if y.ipv4 == _host][0]
            self[_name].nmap = [_host, _result]

        _nm = nm.PortScanner()
        print('ping sweep ....', end='', flush=True)
        _nm.scan(_hosts, arguments='-n -sn -PE -PA22,23,80', sudo=True)
        print('done')
        _ips = _nm.all_hosts()
        print('searching database...', end='', flush=True)
        _results = self.db.get_nmap(hosts=_ips,days=_days)
        print('done')

        _ipd = [_[0] for _ in _results]
        _ips = [_ for _ in _ips if _ not in _ipd]

        for _result in _results:
            if not _result[4][1]['scan']:
                _ips.append(_result[0])
                continue
            print('read   : {}'.format(_result[3]))
            _name = [x for x,y in self.items() if y.ipv4 == _result[0]][0]
            self[_name].nmap = _result[4]


        _ips = sorted([tuple(x.split('.')) for x in _ips])
        _ips = ' '.join(['.'.join(x) for x in _ips])
        if _ips:
            _nm = nm.PortScannerAsync()
            print('scanning ' + _ips)
            print("Waiting for nmap ....")
            _nm.scan(hosts=_ips, ports=_ports, arguments=_arguments,
                sudo=True, callback=do_entry)
            while _nm.still_scanning():
                print('.', end='', flush=True)
                _nm.wait(10)

        print('nmap scan done')

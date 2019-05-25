
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
from pprint import pprint
from datetime import datetime, timedelta
from IPy import IP
from collections import OrderedDict

# __THIS_DIR = os.path.dirname(os.path.abspath(
#     inspect.getframeinfo(inspect.currentframe()).filename
# ))

this_file = os.path.abspath(
    inspect.getframeinfo(inspect.currentframe()).filename)
this_dir = os.path.dirname(this_file)
config = {
    'path': os.path.join(this_dir, 'net.cfg'),
    'db': {
        'path': os.path.join(this_dir, "net.db"),
        'init': False,
        },
    'nmap': {
        'hosts': None,
        'fqdn': None,
        'ip_range': None,
        'days': 7,
        'ports': '5899-5940,3389,23,22',
        # 'arguments': '-O -Pn -R -sV',
        'arguments': '-O -sC -sV -T4',
        'arguments_needing_root': '-O -sS',
        'arguments_port_scan': '-sn -n -PE -PA21-23,80,443,3389,5899-5949',
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
        path=globals()['config']['db']['path'],
        init=globals()['config']['db']['init'],
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

        self.conf['db']['path'] = path
        self.conf['db']['init'] = init

        self.path = self.conf['db']['path']
        self.init = self.conf['db']['init']
        self.conn = sqlite3.connect(
            self.path,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        self.cursor = self.conn.cursor()
        self.data = None

        if self.init is True:
            self.drop_tables()
        self.create_tables()
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
        self.cursor.execute('''
            SELECT name FROM sqlite_master WHERE type='table'
        ''')
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
        with self.conn:
            self.conn.cursor().executescript(
                re.sub(r'\n\s*', '\n', __sql)
            )
        return


    def get_nmap(self,
        hosts=globals()['config']['nmap']['hosts'],
        ports=globals()['config']['nmap']['ports'],
        arguments=globals()['config']['nmap']['arguments'],
        days=globals()['config']['nmap']['days'],
        show=False):

        sql, self.params = [], []

        if hosts:
            # space or comma delimited list of hosts
            # unique
            hosts = list(dict.fromkeys(list(filter(
                lambda x: x,
                re.split('\s+,?\s*|\s*,?\s+', hosts)
            ))))

            self.params += hosts
            sql.append('`host`={}'.format(
                ', '.join(['?'] * len(hosts))
            ))

        if ports:
            ports = list(map(
                lambda x: re.split(r'\s*-\s*', x),
                re.split(r'[\s,]+', ports)
            ))
            ports.sort()
            self.params.append(
                ','.join(list(dict.fromkeys(
                    list(map(lambda x: '-'.join(x), ports))
                )))
            )
            sql.append('`ports`=?')

        if arguments:
            arguments = list(map(
                lambda x: re.sub(r'\s+', ' ', x).strip(),
                arguments.split('-')
            ))
            arguments.sort()
            self.params.append(
                ' '.join(list(map(
                    lambda x: '-' + str(x), arguments
                )))
            )
            sql.append('`arguments`=?')


        if days:
            sql.append('`updated_at`>?')
            self.params.append(datetime.now() - timedelta(days=days))

        if sql:
            sql = ' WHERE ' + ' AND '.join(sql)
        else:
            sql = ''

        self.sql = 'SELECT `host`, `ports`, `arguments`, `command_line`, `data` FROM `nmap`'
        self.sql += sql
        self.sql += ' ORDER BY `host`, `updated_at` DESC'

        self.cursor.execute(self.sql, self.params)
        # self.cursor.execute(self.sql, self.params)
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
            ports = list(map(
                lambda x: re.split(r'\s*-\s*', x),
                re.split(r'[\s,]+', ports)
            ))
            ports.sort()
            ports = ','.join(list(dict.fromkeys(
                list(map(lambda x: '-'.join(x), ports))
            )))

        if arguments:
            arguments = list(map(
                lambda x: re.sub(r'\s+', ' ', x).strip(),
                arguments.split('-')
            ))
            arguments.sort()
            arguments = ' '.join(list(map(
                    lambda x: '-' + str(x), arguments
            )))

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
            # pprint(self.sql)
            # pprint(self.params)
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

DB = db()

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
            arguments_port_scan=globals()['config']['nmap']['arguments_port_scan'],
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
                'arguments_port_scan': arguments_port_scan,
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
        __nm.scan(
            self.hosts,
            arguments=self.conf['nmap']['arguments_port_scan']
        )

        __results = []
        __ip_list_db = []
        __ip_list = __nm.all_hosts()
        __results = self.db.get_nmap(hosts=', '.join(__ip_list))
        # pprint(__ip_list)
        # pprint(__results)
        # sys.exit()
        __ip_list_db = list(map(lambda _: _[0], __results))

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
            __ip_list = list(filter(
                lambda _: _ not in __ip_list_db, __ip_list
            ))

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
        self.__ldap = None
        self.__nmap = None
        self.__name = None
        self.distinguishedName = None
        self.dNSHostName = None
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
            if 'dNSHostName' in ldap.keys():
                self.dNSHostName = ldap['dNSHostName'][0]
            if 'distinguishedName' in ldap.keys():
                self.distinguishedName = ldap['distinguishedName'][0]
            if 'operatingSystem' in ldap.keys():
                self.operatingSystem = ldap['operatingSystem'][0]
            if 'operatingSystemVersion' in ldap.keys():
                self.operatingSystemVersion = ldap['operatingSystemVersion'][0]

    @property
    def nmap(self):
        return self.__nmap

    @nmap.setter
    def nmap(self, nmap):
        self.__nmap = nmap
        if nmap:
            # do this before addresses
            # _n = nmap[4][1]['scan'][nmap[0]]
            # pprint(type(nmap))
            # sys.exit()
            _n = nmap[1]['scan'][nmap[0]]
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
    def dNSHostName(self):
        return self.__dNSHostName

    @dNSHostName.setter
    def dNSHostName(self, dNSHostName):
        self.__dNSHostName = dNSHostName
        if dNSHostName and dNSHostName != '':
            self.__name = dNSHostName.split('.')[0]

    @property
    def operatingSystem(self):
        if self.__operatingSystem:
            return self.__operatingSystem
        if self.__ldap and 'operatingSystem' in self.__ldap.keys():
            self.operatingSystem = self.__ldap['operatingSystem'][0]


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
                self.__dNSHostName = self.name + '.' + self.domain


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
            nmap_arguments_port_scan=globals()['config']['nmap']['arguments_port_scan'],
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
                'arguments_port_scan': nmap_arguments_port_scan,
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

    def nmap_scan(self, hosts):
        for __host in self.nm.scan(hosts):
            __c = host()
            __c.nmap = __host[4]
            self.append(__c)

    def ldap_scan(self):

        __nmap_results = []
        __results = []

        __groups = self.ld.search(
            search_filter='(objectClass=group)',
            attributes=['name', 'member']
        )
        if __groups:
            __groups = list(map(
                lambda x: [
                    x['attributes']['name'][0],
                    x['attributes']['member']
                ], __groups
            ))

        __scan = self.ld.search(
            search_filter='(objectClass=computer)',
            attributes=['*']
        )

        for _d in __scan:
            if 'objectClass' in _d['attributes'].keys() and (
                'computer' in _d['attributes']['objectClass']):
                __name = _d['attributes']['name'][0].lower()
                if not __name in self.keys():
                    self[__name] = host()
                self[__name].ldap = _d['attributes']
                self[__name].groups = list(map(
                    lambda x: x[0],
                    list(filter(
                        lambda x: _d['attributes']['distinguishedName'][0] in x[1], __groups
                    ))
                ))
                if self[__name].dNSHostName and self[__name].os == 'windows':
                    self[__name].tcp = {
                        22: { 'name': 'ssh' },
                        3389: { 'name': 'ms-wbt-server' },
                        5899: { 'name': 'vnc' } }
                else:
                    __nscan = self.nm.scan(__name + '.' + self.ld.fqdn)
                    if __nscan:
                        self[__name].nmap = __nscan[0][4]

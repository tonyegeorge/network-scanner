
import IPy as ip
import copy
import inspect
import itertools
import json
import jsonpickle
import ldap3 as ldap
import logging
import netifaces
import nmap
import os
import psycopg2 as postgres
import pymysql as mysql
import re
import sqlite3
import sys
import warnings
from collections import OrderedDict
from configparser import ConfigParser, RawConfigParser, NoSectionError, NoOptionError
from datetime import datetime, timedelta
from pprint import pprint
from pypsrp.client import Client
from textwrap import dedent
from inspect import currentframe, getframeinfo

this_file = getframeinfo(currentframe()).filename
this_file = os.path.abspath(this_file)
this_dir = os.path.dirname(this_file)
cfg_file = re.sub(r'\.py$', '.cfg', this_file)
log_file = re.sub(r'\.py$', '.log', this_file)
db_file = re.sub(r'\.py$', '.db', this_file)

ports  = '22,23,42,53,67,80-88,'
ports += '135-139,389,443-445,636,'
ports += '1512,3000,3268,3269,3389,5899-5986,8080'



config = {
    'path': cfg_file,
    'db': {
        'engine': 'sqlite',
        'init': False,
        'path': db_file,
        'host': 'localhost',
        'port': None,
        'user': None,
        'password': None,
        'database': 'net_db',
        },
    'dns': {
        'server': None,
        'days': 7,
        },
    'nmap': {
        'hosts': None,
        'fqdn': None,
        'ip_range': None,
        'days': 7,
        'ports': ports,
        'arguments': '-O -Pn -R -sC -sV -T4',
        'arguments_needing_root': '-O -sS',
        'ping': '-n -sn -PE -PA22,23,80',
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
    'log': {
        'file': os.path.split(this_file)[0] + '.log',
        'level': logging.DEBUG,
        'format': "%(asctime)s: %(levelname)s: %(message)s",
        },
    }

def mergeConf(dict1, dict2):
    for k1,v1 in dict2.items():
        for k2,v2 in v1.items():
            if v2 is not None:
                if k1 in dict1.keys():
                    dict1[k1][k2] = v2
                else:
                    dict1[k1] = {k2:v2}

def strip0(sql):
    res = re.sub(r'\s*\n\s*', '\n', sql)
    res = re.sub(r'^\n', '', res)
    res = re.sub(r'\n$', '', res).strip()
    return res

def strip1(sql):
    res = re.sub(r'\s*\n\s*', ' ', sql)
    res = re.sub(r'\s+', ' ', res).strip()
    return res

parser = ConfigParser()
parser.read(config['path'])
mergeConf(config, {
    k: dict(parser.items(k))
    for k in parser.sections()
})

def connected_networks():

    calc = netifaces.interfaces()
    calc = [netifaces.ifaddresses(x) for x in calc]
    calc = [x[netifaces.AF_INET] for x in calc if
           netifaces.AF_INET in x.keys()]
    calc = list(itertools.chain.from_iterable(calc))
    calc = [x for x in calc if
           not x['addr'].startswith('127.') and 'netmask' in x.keys()]

    res = ip.IPSet()
    for cal in calc:
        res.add(ip.IP(cal['addr'] + '/' + cal['netmask'], make_net=True))

    return res

def sort_hosts(hosts, discard_non_ip=False):
    if isinstance(hosts, list):
        hosts = ','.join(hosts)
    if isinstance(hosts, str):
        hosts = re.sub(r'[\s,]+', ' ', hosts).strip().split()
        hosti = ip.IPSet()
        hostd = []
        for host in hosts:
            try:
                hosti.add(ip.IP(host))
            except:
                if not discard_non_ip is True:
                    hostd.append(host)
        hosts = []
        for x in hosti:
            for y in x:
                hosts.append(y.strNormal())
        hosts += sorted(hostd)
        hosts = ' '.join(hosts)
    return(hosts)

def sort_ports(ports):
    if isinstance(ports, list):
        ports = ','.join(ports)
    ports = re.sub(r'\n', ' ', ports)
    ports = re.split(r'[\s,]+', ports)
    ports = [x.split('-') for x in ports]
    ports = [[int(x) for x in y] for y in ports]
    ports.sort()
    ports = [[str(x) for x in y] for y in ports]
    ports = ['-'.join(x) for x in ports]
    ports = ','.join(ports)
    return ports

def sort_arguments(arguments):
    if isinstance(arguments, list):
        arguments = [re.sub(r'^(\s*-\s*)+', '', x) for
            x in arguments]
    else:
        arguments = arguments.split('-')
    arguments = [x.strip() for x in arguments if x]
    arguments.sort()
    arguments = ['-' + x for x in arguments]
    arguments = ' '.join(arguments)
    return arguments

class db():

    def __init__(self, engine=None, path=None, host=None, port=None,
        user=None, password=None, database=None,
        config_file=None, config=None,):

        if not config:
            config=globals()['config']['db']
        if 'db' in config.keys() and isinstance(config['db'], dict):
            config=config['db']

        if config_file and os.path.isfile(config_file):
            parser.read(config_file)
            config.update({k:v for k,v in parser['db'].items() if v})

        self.engine = config.get('engine') if not engine else engine
        self.path = config.get('path') if not path else path
        self.host = config.get('host') if not host else host
        self.port = config.get('port') if not port else port
        self.user = config.get('user') if not user else user
        self.password = config.get('password') if not password else password
        self.database = config.get('database') if not database else database

        if self.engine == 'mysql':
            self.p = '%s'
            if not self.port or self.port == '':
                self.port = 3306
            else:
                self.port = int(self.port)

        elif self.engine == 'postgres':
            self.p = '%s'
            if not self.port or self.port == '':
                self.port = 5432
            else:
                self.port = int(self.port)

        elif self.engine == 'sqlite':
            self.p = '?'

        self.sql = None
        self.data = None

        self.connect()


    def connect(self):

        if self.engine == 'mysql':
            print('connecting to {} {} ...'.format(
                self.engine, self.database
            ), end='', flush=True)
            try:
                self.connection = mysql.connect(
                    host=self.host,
                    port=self.port,
                    user=self.user,
                    password=self.password,
                    database=self.database,
                )
            except:
                print('failed mysql connection error')
                print(sys.exc_info()[1])
                self.connection = None
                sys.exit()
            else:
                print('done')
                self.cursor = self.connection.cursor()

        elif self.engine == 'postgres':
            print('connecting to {} {} ...'.format(
                self.engine, self.database
            ), end='', flush=True)
            try:
                self.connection = postgres.connect(
                    host=self.host,
                    port=self.port,
                    user=self.user,
                    password=self.password,
                    database=self.database,
                )
            except:
                print('failed postgres connection error')
                print(sys.exc_info()[1])
                self.connection = None
                sys.exit()
            else:
                print('done')
                self.cursor = self.connection.cursor()

        elif self.engine == 'sqlite':
            print('connecting to {} {} ...'.format(
                self.engine, self.path
            ), end='', flush=True)
            try:
                self.connection = sqlite3.connect(
                    self.path,
                    detect_types=sqlite3.PARSE_DECLTYPES,)
            except:
                print('failed sqlite connection error')
                print(sys.exc_info()[1])
                self.connection = None
                sys.exit()
            else:
                print('done')
                self.cursor = self.connection.cursor()
                self.cursor.execute('PRAGMA journal_mode=wal')
                self.connection.commit()

    def columns(self, table=None, show=False):
        if not table:
            return self.tables(True, show)
        else:
            if not isinstance(table, str):
                return
        self.cursor.execute('SELECT * FROM {} LIMIT 1'.format(table))
        self.data = [x[0] for x in self.cursor.description]
        if show is True:
            print(table)
            print('-' * len(table))
            for r in self.data:
                print (r)
        return(self.data)

    def tables(self, columns=False, show=False):
        if self.engine == 'mysql':
            self.data = self.get('SHOW TABLES', True)
        elif self.engine == 'postgres':
            self.data = self.get(dedent('''\
            SELECT tablename FROM pg_catalog.pg_tables
            WHERE schemaname = 'public'
            '''), True)
        elif self.engine == 'sqlite':
            self.data = self.get((dedent('''\
            SELECT name FROM sqlite_master WHERE type = 'table'
            ''')), True)
        self.data = [x[0] for x in self.data]
        if columns is True:
            self.data = [(x, self.columns(x)) for x in self.data]
        if show is True:
            pprint(self.data)
        return self.data

    def get(self, sql, all=False, show=False):

        if isinstance(sql, str):
            self.sql = sql
            self.cursor.execute(self.sql)
        elif isinstance(sql, list):
            self.sql = tuple(sql)
            self.cursor.execute(*self.sql)
        elif isinstance(sql, tuple):
            self.sql = sql
            self.cursor.execute(*self.sql)

        if all is False:
            self.data = self.cursor.fetchone()
        else:
            self.data = self.cursor.fetchall()
        if show is True:
            pprint(self.data)
        return self.data

    def set(self, sql, commit=True):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            if isinstance(sql, str):
                self.sql = sql
                self.cursor.execute(self.sql)
            elif isinstance(sql, list):
                self.sql = tuple(sql)
                self.cursor.execute(*self.sql)
            elif isinstance(sql, tuple):
                self.sql = sql
                self.cursor.execute(*self.sql)

        if not commit is False:
            self.connection.commit()

class net_db(db):
    '''
    ** mysql **

    CREATE DATABASE net_db;
    CREATE USER 'net_db'@'%' IDENTIFIED WITH mysql_native_password BY 'net_db';
    CREATE USER 'net_db'@'localhost' IDENTIFIED WITH mysql_native_password BY 'net_db';
    GRANT ALL PRIVILEGES ON net_db.* TO 'net_db'@'%';
    GRANT ALL PRIVILEGES ON net_db.* TO 'net_db'@'localhost';

    '''
    def __init__(self, engine=None, path=None, host=None, port=None,
        user=None, password=None, database=None, init=None,
        config_file=globals()['config']['path'],
        config=None,):

        if not config:
            config=globals()['config']['db']
        if 'db' in config.keys() and isinstance(config['db'], dict):
            config=config['db']

        super().__init__(engine, path, host, port, user, password,
            database, config_file, config)

        if init is True:
            self.drop_tables()
            self.create_tables()


    def drop_tables(self):
        for t in self.tables():
            print('dropping table {} ...'.format(t), end='', flush=True)
            self.set('DROP TABLE IF EXISTS ' + t, False)
            print('done')
        self.connection.commit()

    def create_tables(self):

        i, u = 'INTEGER PRIMARY KEY', ''
        if self.engine == 'mysql':
            i = 'INT PRIMARY KEY AUTO_INCREMENT'
            u = ' ON UPDATE CURRENT_TIMESTAMP'
        elif self.engine == 'postgres':
            i = 'serial PRIMARY KEY'

        print('creating table dns ...', end='', flush=True)
        self.cursor.execute(dedent('''\
        CREATE TABLE dns (
        id {},
        server VARCHAR(64) NOT NULL,
        data JSON,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP{}
        );'''.format(i, u)))
        print('done')
        print('creating indexes on dns ...', end='', flush=True)
        self.cursor.execute('CREATE INDEX dns_server_idx ON dns (server);')
        self.cursor.execute('CREATE INDEX dns_updated_at_idx ON dns (updated_at);')
        print('done')

        print('creating table ldap ...', end='', flush=True)
        self.cursor.execute(dedent('''\
        CREATE TABLE ldap (
        id {},
        server VARCHAR(64) NOT NULL,
        search_base VARCHAR(255) NOT NULL,
        search_filter VARCHAR(255) NOT NULL,
        attributes VARCHAR(255) NOT NULL,
        data JSON NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP{}
        );'''.format(i, u)))
        print('done')
        print('creating indexes on ldap ...', end='', flush=True)
        self.cursor.execute('CREATE INDEX ldap_server_idx  ON ldap (server);')
        self.cursor.execute('CREATE INDEX ldap_search_base_idx  ON ldap (search_base);')
        self.cursor.execute('CREATE INDEX ldap_search_filter_idx  ON ldap (search_filter);')
        self.cursor.execute('CREATE INDEX ldap_attributes_idx  ON ldap (attributes);')
        self.cursor.execute('CREATE INDEX ldap_updated_at_idx  ON ldap (updated_at);')
        print('done')

        print('creating table nmap ...', end='', flush=True)
        self.cursor.execute(dedent('''\
        CREATE TABLE IF NOT EXISTS nmap (
        id {},
        host VARCHAR(32) NOT NULL,
        ports VARCHAR(255) NOT NULL DEFAULT '',
        arguments VARCHAR(255) NOT NULL DEFAULT '',
        command_line VARCHAR(255) NOT NULL DEFAULT '',
        data JSON,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP{}
        );'''.format(i, u)))
        print('done')
        print('creating indexes on nmap ...', end='', flush=True)
        self.cursor.execute('CREATE INDEX nmap_host_idx  ON nmap (host);')
        self.cursor.execute('CREATE INDEX nmap_ports_idx  ON nmap (ports);')
        self.cursor.execute('CREATE INDEX nmap_arguments_idx  ON nmap (arguments);')
        self.cursor.execute('CREATE INDEX nmap_updated_at_idx  ON nmap (updated_at);')
        print('done')

        if self.engine == 'postgres':
            print('creating function set_timestamp ...', end='', flush=True)
            self.set(dedent('''\
            CREATE OR REPLACE FUNCTION set_timestamp()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = NOW();
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
            '''), False)
            print('done')

        for table in self.tables(columns=True):
            t = table[0] + '_updated_at'

            if self.engine == 'postgres':
                print('creating trigger {} ...'.format(t), end='', flush=True)
                self.set(dedent('''\
                CREATE TRIGGER {}
                BEFORE UPDATE ON {}
                FOR EACH ROW
                EXECUTE PROCEDURE set_timestamp()
                '''.format(t, table[0])), False)
                print('done')

            elif self.engine == 'sqlite':
                c = ', '.join([x for x in table[1] if x != 'updated_at' ])
                print('creating trigger {} ...'.format(t), end='', flush=True)
                self.set(dedent('''\
                CREATE TRIGGER {0}
                BEFORE UPDATE OF {1} ON {2}
                BEGIN
                    UPDATE {2}
                    SET updated_at = CURRENT_TIMESTAMP
                    WHERE id = id;
                END;
                '''.format(t, c, table[0])), False)
                print('done')

        self.connection.commit()

my_db = None

def get_dns(db=None, server=None, days=None, fetchall=False, show=False,
    config_file=globals()['config']['path'],
    config=None,
    ):

    global my_db
    if not db:
        if not my_db:
            my_db = net_db()
        db = my_db

    if not config:
        config=globals()['config']['dns']
    if 'dns' in config.keys() and isinstance(config['dns'], dict):
        config=config['dns']

    if config_file and os.path.isfile(config_file):
        parser.read(config_file)
        config.update({k:v for k,v in parser['dns'].items() if v})

    # server = config.get('server') if not server else server
    days = config.get('days') if not days else days

    sql = [[],[]]

    if server:
        if isinstance(server, str):
            server = re.split(r'[\s,]+', server)

        sql[0].append('server IN ({})'.format(
            ', '.join([db.p]*len(server))
        ))
        sql[1] += server

    if days:
        sql[0].append('updated_at > ' + db.p)
        sql[1].append(datetime.now() - timedelta(days=int(days)))

    if sql[0]:
        sql[0] = 'WHERE ' + ' AND '.join(sql[0])
    else:
        sql[0] = ''

    sql[0] = dedent('''\
    WITH current AS (
        SELECT * FROM dns
        {}
    ), latest AS (
        SELECT server, MAX(updated_at) AS updated_at
        FROM current
        GROUP by server
    )
    SELECT current.*
    FROM current JOIN latest
    ON current.server = latest.server
    AND current.updated_at = latest.updated_at
    ORDER BY current.server, current.updated_at DESC
    '''.format(sql[0]))

    result = db.get(sql, fetchall)
    if result:
        if not server or fetchall is True:
            if db.engine != 'postgres':
                result = [
                    x[:2] + (json.loads(x[2]),) + x[3:] for
                    x in result ]
        else:
            if db.engine != 'postgres':
                result = result[:2] + (json.loads(result[2]),) + result[3:]
    if show is True:
        pprint(result)
    return result

def set_dns(db=None, server=None, data=None):

    if not data:
        return

    global my_db
    if not db:
        if not my_db:
            my_db = net_db()
        db = my_db

    if not server:
        server = config['dns']['server']

    db.set((dedent('''\
    INSERT INTO dns (server, data) VALUES ({0},
    {0}
    )'''.format(db.p)),
    (server, json.dumps(data))))

def get_nmap(db=None, hosts=None,
    ports=None, arguments=None, days=None,
    fetchall=False, show=False,):

    global my_db
    if not db:
        if not my_db:
            my_db = net_db()
        db = my_db

    sql = [[],[]]

    if fetchall is False:
        if not ports:
            ports = config['nmap']['ports']
        if not arguments:
            arguments = config['nmap']['arguments']
        if not days:
            days = config['nmap']['days']

    if hosts:
        hosts = sort_hosts(hosts, True)
        if isinstance(hosts,str):
            hosts = hosts.split()
        sql[0].append('host IN ({})'.format(
            ', '.join([db.p] * len(hosts))))
        sql[1] += hosts

    if ports:
        ports = sort_ports(ports)
        sql[0].append('ports = ' + db.p)
        sql[1].append(ports)

    if arguments:
        arguments = sort_arguments(arguments)
        sql[0].append('arguments = ' + db.p)
        sql[1].append(arguments)

    if days:
        sql[0].append('updated_at > ' + db.p)
        sql[1].append(datetime.now() - timedelta(days=int(days)))

    if sql[0]:
        sql[0] = ' WHERE ' + ' AND '.join(sql[0])
    else:
        sql[0] = ''

    sql[0] = (dedent('''\
    WITH current AS (
    SELECT * FROM nmap{}
    ), latest AS (
    SELECT host, MAX(updated_at) AS updated_at
    FROM current
    GROUP by host
    )
    SELECT * FROM current JOIN latest
    ON current.host = latest.host
    AND current.updated_at = latest.updated_at
    ORDER BY current.host, current.updated_at DESC
    '''.format(sql[0])))


    fetchall = not hosts or fetchall
    result = db.get(sql, fetchall)

    if result and db.engine != 'postgres':
        if fetchall is True:
            result = [ x[:5] + (json.loads(x[5]),) + x[6:] for x in result ]
        else:
            result = result[:5] + (json.loads(result[5]),) + result[6:]

    if show is True:
        pprint(result)

    return result

def set_nmap(db=None,
    host=None, ports=None, arguments=None,
    command_line=None, data=None):

    global my_db
    if not db:
        if not my_db:
            my_db = net_db()
        db = my_db

    if not (host and data):
        return

    sql = [[], []]

    if host:
        host = host.strip().lower()
        sql[0].append('host')
        sql[1].append(host)

    if ports:
        ports = sort_ports(ports)
        sql[0].append('ports')
        sql[1].append(ports)

    if arguments:
        arguments = sort_arguments(arguments)
        sql[0].append('arguments')
        sql[1].append(arguments)

    if command_line:
        sql[0].append('command_line')
        sql[1].append(command_line)

    sql[0].append('data')
    sql[1].append(json.dumps(data))

    sql[0] = dedent('''\
    INSERT INTO nmap ({})
    VALUES ({})
    '''.format(
        ', '.join(sql[0]),
        ', '.join([db.p] * len(sql[0]))
    ))
    db.set(sql)


def get_ldap(db=None, server=None, search_base=None, search_filter=None,
    attributes=None, days=None, show=False, fetchall=False):

    global my_db
    if not db:
        if not my_db:
            my_db = net_db()
        db = my_db

    sql = [[],[]]

    if all is False:
        if not server:
            server = config['ldap']['server']
        if not search_base:
            search_base = config['ldap']['search_base']
        if not search_filter:
            search_filter = config['ldap']['search_filter']
        if not attributes:
            attributes = ldap.ALL_ATTRIBUTES
        if not days:
            days = config['ldap']['days']

    if server:
        if isinstance(server, str):
            server = re.split(r'[\s,]+', server)

        sql[0].append('server IN ({})'.format(
            ', '.join([db.p]*len(server))
        ))
        sql[1] += server

    if search_base:
        sql[0].append('search_base = ' + db.p)
        sql[1].append(search_base)

    if search_filter:
        sql[0].append('search_filter = ' + db.p)
        sql[1].append(search_filter)

    if attributes:
        sql[0].append('attributes = ' + db.p)
        sql[1].append(json.dumps(attributes))

    if days:
        sql[0].append('updated_at > ' + db.p)
        sql[1].append(datetime.now() - timedelta(days=int(days)))

    if sql[0]:
        sql[0] = 'WHERE ' + ' AND '.join(sql[0])
    else:
        sql[0] = ''

    sql[0] = dedent('''\
    WITH current AS (
        SELECT * FROM ldap
        {}
    ), latest AS (
        SELECT server, MAX(updated_at) AS updated_at
        FROM current
        GROUP by server
    )
    SELECT current.*
    FROM current JOIN latest
    ON current.server = latest.server
    AND current.updated_at = latest.updated_at
    ORDER BY current.server, current.updated_at DESC
    '''.format(sql[0]))

    fetchall = not server or fetchall is True
    result = db.get(sql, fetchall)

    if result and db.engine != 'postgres':
        if fetchall is True:
            result = [ x[:5] + (json.loads(x[5]),) + x[6:] for x in result ]
        else:
            result = result[:5] + (json.loads(result[5]),) + result[6:]

    if show is True:
        pprint(result)

    return result


def set_ldap(db=None, server=None,
    search_base=None, search_filter=None, attributes=None,
    data=None):

    global my_db
    if not db:
        if not my_db:
            my_db = net_db()
        db = my_db

    if not (server and data and (
        search_base or search_filter or attributes)):
        return

    sql = [[], []]

    sql[0].append('server')
    sql[1].append(server)

    if search_base:
        sql[0].append('search_base')
        sql[1].append(search_base)

    if search_filter:
        sql[0].append('search_filter')
        sql[1].append(search_filter)

    if attributes:
        sql[0].append('attributes')
        sql[1].append(json.dumps(attributes))

    sql[0].append('data')
    sql[1].append(json.dumps(data))

    sql[0] = dedent('''\
    INSERT INTO ldap ({})
    VALUES ({})
    '''.format(
        ', '.join(sql[0]),
        ', '.join([db.p] * len(sql[0]))
    ))

    db.set(sql)

class host_object():

    def __init__(self,
        build = None,
        dNSDomainName = None,
        dNSHostName = None,
        dNSHostNames = [],
        fqhn = [],
        groups = [],
        ipv4 = None,
        ldap = {},
        name = None,
        names = [],
        nmap = {},
        operatingSystem = None,
        operatingSystemVersion = None,
        osFamily = None,
        osType = None,
        osVersion = None,
        tcp = {},
    ):

        self.__build = build
        self.__dNSDomainName = dNSDomainName
        self.__dNSHostName = dNSHostName
        self.__dNSHostNames = dNSHostNames
        self.__fqhn = fqhn
        self.__groups = groups
        self.__ipv4 = ipv4
        self.__ldap = ldap
        self.__name = name
        self.__names = names
        self.__nmap = nmap
        self.__operatingSystem = operatingSystem
        self.__operatingSystemVersion = operatingSystemVersion
        self.__osFamily = osFamily
        self.__osType = osType
        self.__osVersion = osVersion
        self.__tcp = tcp

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
    def fqhn(self):
        return self.__fqhn

    @fqhn.setter
    def fqhn(self, val):
        if isinstance(val, str):
            val = re.split(r'[\s,]+', val)
        elif isinstance(val, dict):
            val = [x['name'] for x in val if 'name' in val.keys()]
        self.__fqhn = sorted(list(
            set(self.__fqhn).union(
            set([x.lower() for x in val]))
        ))

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
        if val and self.osFamily == 'windows':
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

def dns_search(server=None, domain=None, user=None, password=None,
    days=None, db=None, host_dict={},
    config_file=config['path'],
    config=None,
    ):

    global my_db
    if not db:
        if not my_db:
            my_db = net_db()
        db = my_db

    if not config:
        config=globals()['config']['dns']
    if 'dns' in config.keys() and isinstance(config['dns'], dict):
        config=config['dns']

    if config_file and os.path.isfile(config_file):
        parser.read(config_file)
        config.update({k:v for k,v in parser['dns'].items() if v})

    server = config.get('server') if not server else server
    domain = config.get('domain') if not domain else domain
    user = config.get('user') if not user else user
    password = config.get('password') if not password else password
    days = config.get('days') if not days else days
    if domain:
        username = domain + '\\' + user
    else:
        username = user

    def search():
        dns_client = Client(server, username=username, password=password,
            ssl=False)
        ps = """
        $Zones = @(Get-DnsServerZone)
        ForEach ($Zone in $Zones) {
            $Zone | Get-DnsServerResourceRecord |
            where {$_.RecordType -eq "A" `
            -and $_.HostName -NotMatch "@|\._msdcs$|(Domain|Forest)DnsZones"} |
            Select-Object HostName -ExpandProperty RecordData |
            Select-Object IPv4Address, HostName, @{l="Zone";e={$Zone.ZoneName}}
        }
        """
        stdout, stderr, rc = dns_client.execute_ps(ps)
        res = [x.split() for x in stdout.split('\n') if x][2:]
        res = sorted([[x[0], (x[1] + '.' + x[2]).lower()] for x in res])
        res = itertools.groupby(res, lambda x: x[0])
        res = [[k,[x[1] for x in list(v)]] for k,v in res]
        res = [[ip.IP(x[0]).int(), x[0], x[1]] for x in res]
        res = [x[1:] for x in sorted(res)]
        return res

    res = get_dns(db=db, server=server, days=days)

    if res:
        print('read cached dns {}'.format(server))
        res = res[2]
    else:
        print('searching dns {} ...'.format(server),
              end='', flush=True)
        res = search()
        print('done')
        print('saving dns search {} ...'.format(server), end='', flush=True)
        set_dns(db, server, res)
        print('done')

    for s in res:
        f = None

        for n in s[1]:
            if n in host_dict.keys():
                f = n
                break
            if not f:
                for k,v in host_dict.items():
                    if n in v.fqhn:
                        f = k
                        break
        if not f:
            f = sorted(s[1])[0]
            host_dict[f] = host_object()
        host_dict[f].ipv4 = s[0]
        host_dict[f].fqhn = s[1]

    return host_dict

def ldap_search(server=None, fqdn=None, domain=None,
    user=None, password=None, days=None,
    config_file=config['path'], config=None,
    db=None, host_dict={},
    ):

    global my_db
    if not db:
        if not my_db:
            my_db = net_db()
        db = my_db

    if not config:
        config=globals()['config']['ldap']
    if 'ldap' in config.keys() and isinstance(config['ldap'], dict):
        config=config['ldap']

    if config_file and os.path.isfile(config_file):
        parser.read(config_file)
        config.update({k:v for k,v in parser['ldap'].items() if v})

    server = config.get('server') if not server else server
    fqdn = config.get('fqdn') if not fqdn else fqdn
    domain = config.get('domain') if not domain else domain
    user = config.get('user') if not user else user
    password = config.get('password') if not password else password
    days = config.get('days') if not days else days
    search_scope = ldap.SUBTREE
    search_filter ='(objectClass=computer)'
    attributes = ldap.ALL_ATTRIBUTES
    search_base = ','.join(['dc=' + x for x in fqdn.split('.')])

    conn = None

    def search(
        server=server,
        search_base=search_base,
        search_filter=search_filter,
        attributes=attributes,
        days=days,
    ):
        nonlocal conn

        res = get_ldap(db=db,
            server=server,
            search_base=search_base,
            search_filter=search_filter,
            attributes=attributes,
            days=days,
        )

        if res:
            print('read cached ldap {} {}'.format(server, search_filter))
            res = res[5]
            return res
        else:
            if not conn:
                try:
                    print('connecting to ldap server {} ...'.format(server),
                          end='', flush=True)
                    conn = ldap.Connection(
                        server='ldap://' + server,
                        user=domain + '\\' + user,
                        password=password,
                        authentication=ldap.NTLM,
                        auto_bind=True,
                    )
                    print('done')
                except:
                    print(sys.exc_info()[1])
                    return []

            print('search ldap {} {} ...'.format(server, search_filter),
                end='', flush=True)
            conn.search(
                search_base=search_base,
                search_scope=search_scope,
                search_filter=search_filter,
                attributes=attributes,
            )
            print('done')

            # beacause of a couple of datetime fields in the output
            # we have to use the ldap3 lib to convert the entry to json
            # then use json lib to bring it back to dict
            res = [json.loads(x.entry_to_json()) for x in conn.entries]

            print('saving ldap {} {} ...'.format(server, search_filter),
                end='', flush=True)
            set_ldap(db=db,
                server=server,
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes,
                data=res
            )
            print('done')
        return res

    groups = search(search_filter='(objectClass=group)', attributes=['name', 'member'])
    groups = [[x['attributes']['name'][0], x['attributes']['member'],] for x in groups]
    res = search(search_filter='(objectClass=computer)', attributes=['*'])
    for s in res:
        if 'objectClass' in s['attributes'].keys() and (
            'computer' in s['attributes']['objectClass']):
            n = s['attributes']['name'][0]
            n = (n + '.' + fqdn).lower()
            f = None
            if n in host_dict.keys():
                f = n
            else:
                for k,v in host_dict.items():
                    for x in v.fqhn:
                        if n == x:
                            host_dict[n] = host_dict[k]
                            f = n
                            break
                    if f:
                        del host_dict[k]
                        break
            if not f:
                f = n
                host_dict[f] = host_object()
            host_dict[f].ldap = s['attributes']
            host_dict[f].groups = [x[0] for
            x in groups if s['attributes']['distinguishedName'][0] in x[1]]

    return host_dict


def nmap_scan(hosts=None, fqdn=None, ip_range=None, days=None,
    ports=None, arguments=None,
    config_file=config['path'], config=None,
    network=False, db=my_db, host_dict={},
    ):

    global my_db
    if not db:
        if not my_db:
            my_db = net_db()
        db = my_db

    if not config:
        config=globals()['config']['nmap']
    if 'nmap' in config.keys() and isinstance(config['nmap'], dict):
        config=config['nmap']

    if config_file and os.path.isfile(config_file):
        parser.read(config_file)
        config.update({k:v for k,v in parser['nmap'].items() if v})

    fqdn = config.get('fqdn') if not fqdn else fqdn
    ip_range = config.get('ip_range') if not ip_range else ip_range
    days = config.get('days') if not days else days
    ports = config.get('ports') if not ports else ports
    arguments = config.get('arguments') if not arguments else arguments

    output = {}

    def set_dict(ip, result):
        if 'scan' not in result.keys():
            return
        f = None
        for k,v in host_dict.items():
            if v.ipv4 and v.ipv4 == ip:
                f = k
                break
        if not f:
            s = result['scan'][ip]
            if 'hostnames' in s.keys():
                for h in s['hostnames']:
                    if h['name'] in host_dict.keys():
                        f = h['name']
                        break
                if not f:
                    f = s['hostnames'][0]['name']
                    host_dict[f] = host_object()
        if not f:
            f = ip
            host_dict[f] = host_object()
        host_dict[f].nmap = [ip, result]
        output[f] = host_dict[f]

    def save_entry(ip, result):
        if not result['scan']:
            return
        if db:
            cmd = result['nmap']['command_line']
            set_nmap(db=db,
                host=ip, ports=ports, arguments=arguments,
                command_line=cmd, data=[ip, result])
            print('\nsaved  : {}'.format(cmd))
        set_dict(ip, result)

    def hosts_append(ip, result):
        nonlocal hosts
        hosts.append(ip)


    def ipset_add(ipset, addr):
        try:
            ipset.add(addr)
        except:
            pass

    if not hosts:
        hosts = [v.ipv4 for k,v in host_dict.items() if v.ipv4]
        hosts += (sorted([k for k,v in host_dict.items() if not v.ipv4]))
        hosts = ' '.join(hosts)
    if network is True:
        hosts = hosts + ' ' + ip_range

    hosts = sort_hosts(hosts)
    if hosts == '':
        return

    print('nmap scan ....')
    ps = nmap.PortScanner()
    psa = nmap.PortScannerAsync()

    l = len(hosts.split())
    print('ping {} ....'.format(
        hosts if l < 2 else 'sweep ' + str(l) + ' hosts'
    ), end='', flush=True)
    # ps.scan(hosts, arguments='-n -sn -PE -PA22,23,80', sudo=True)
    ps.scan(hosts, arguments=config['ping'], sudo=True)
    hosts = ps.all_hosts()
    l = len(hosts)
    ls = '1 host' if l == 1 else str(l) + ' hosts'
    print('done. Found {}'.format(ls))
    print('searching database for {} ...'.format(ls), end='', flush=True)
    results = get_nmap(db=db,
        hosts=hosts,
        ports=ports,
        arguments=arguments,
        fetchall=True,
        days=days,
    )
    l = len(results)
    ls = '1 host' if l == 1 else str(l) + ' hosts'
    print('done. Found {}'.format(ls))

    if results:
        hostd = [x[1] for x in results]
        hosts = [x for x in hosts if x not in hostd]
        for result in results:
            if not result[5][1]['scan']:
                hosts.append(result[0])
                continue
            print('read   : {}'.format(result[4]))
            set_dict(result[5][0], result[5][1])

    hosts = sort_hosts(hosts)
    ports = sort_ports(ports)
    arguments = sort_arguments(arguments)

    if hosts:
        psa = nmap.PortScannerAsync()
        l = len(hosts.split())
        ls = '1 host' if l == 1 else str(l) + ' hosts'
        print('scanning {}'.format(ls))
        print("Waiting for nmap ....")
        psa.scan(
            hosts=hosts,
            ports=ports,
            arguments=arguments,
            callback=save_entry,
            sudo=True,
            )
        while psa.still_scanning():
            print('.', end='', flush=True)
            psa.wait(10)

    print('nmap scan done')
    return host_dict


def hosts_dict(
    arguments=None,
    days=None,
    domain=None,
    fqdn=None,
    hosts=None,
    ip_range=None,
    password=None,
    ports=None,
    server=None,
    user=None,
    dns_days=None,
    dns_domain=None,
    dns_password=None,
    dns_server=None,
    dns_user=None,
    ldap_days=None,
    ldap_domain=None,
    ldap_fqdn=None,
    ldap_password=None,
    ldap_server=None,
    ldap_user=None,
    nmap_arguments=None,
    nmap_days=None,
    nmap_fqdn=None,
    nmap_hosts=None,
    nmap_ip_range=None,
    nmap_ports=None,
    config_file=config['path'], config={},
    db=None, host_dict={},
    ):

    global my_db
    if not db:
        if not my_db:
            my_db = net_db()
        db = my_db

    if not config:
        config=globals()['config']

    if config_file and os.path.isfile(config_file):
        parser.read(config_file)
        mergeConf(config, {
            k: dict(parser.items(k))
            for k in parser.sections()
        })

    if not dns_server: dns_server = server if server else config.get('dns', {}).get('server', None)
    if not dns_user: dns_user = user if user else config.get('dns', {}).get('user', None)
    if not dns_domain: dns_domain = domain if domain else config.get('dns', {}).get('domain', None)
    if not dns_password: dns_password = password if password else config.get('dns', {}).get('password', None)
    if not dns_days: dns_days = days if days else config.get('dns', {}).get('days', None)

    if not ldap_server: ldap_server = server if server else config.get('ldap', {}).get('server', None)
    if not ldap_fqdn: ldap_fqdn = fqdn if fqdn else config.get('ldap', {}).get('fqdn', None)
    if not ldap_user: ldap_user = user if user else config.get('ldap', {}).get('user', None)
    if not ldap_domain: ldap_domain = domain if domain else config.get('ldap', {}).get('domain', None)
    if not ldap_password: ldap_password = password if password else config.get('ldap', {}).get('password', None)
    if not ldap_days: ldap_days = days if days else config.get('ldap', {}).get('days', None)

    if not nmap_hosts: nmap_hosts = hosts if hosts else config.get('nmap', {}).get('hosts', None)
    if not nmap_fqdn: nmap_fqdn = fqdn if fqdn else config.get('nmap', {}).get('fqdn', None)
    if not nmap_ip_range: nmap_ip_range = ip_range if ip_range else config.get('nmap', {}).get('ip_range', None)
    if not nmap_days: nmap_days = days if days else config.get('nmap', {}).get('days', None)
    if not nmap_ports: nmap_ports = ports if ports else config.get('nmap', {}).get('ports', None)
    if not nmap_arguments: nmap_arguments = arguments if arguments else config.get('nmap', {}).get('arguments', None)

    dns_search(
        server=dns_server,
        user=dns_user,
        domain=dns_domain,
        password=dns_password,
        days=dns_days,
        db=db,
        host_dict=host_dict,
    )

    ldap_search(
        server=ldap_server,
        fqdn=ldap_fqdn,
        domain=ldap_domain,
        user=ldap_user,
        password=ldap_password,
        days=ldap_days,
        db=db,
        host_dict=host_dict,
    )

    nmap_scan(
        hosts=nmap_hosts,
        fqdn=nmap_fqdn,
        ip_range=nmap_ip_range,
        days=nmap_days,
        ports=nmap_ports,
        arguments=nmap_arguments,
        db=db,
        host_dict=host_dict,
    )

    return host_dict


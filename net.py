
import json
import ldap3 as ldap
import nmap
import socket
import IPy
import netifaces

import utils
from utils import *

# from collections import OrderedDict
# from configparser import ConfigParser, RawConfigParser, NoSectionError, NoOptionError
from datetime import datetime, timedelta
from pypsrp.client import Client
from textwrap import dedent
from inspect import currentframe, getframeinfo

this_file = getframeinfo(currentframe()).filename
this_file = os.path.abspath(this_file)
this_dir = os.path.dirname(this_file)
cfg_file = re.sub(r'\.py$', '.cfg', this_file)
log_file = re.sub(r'\.py$', '.log', this_file)
db_file = re.sub(r'\.py$', '.db', this_file)

# just doing this so the lines dont exceed 80 columns
ports  = '22,23,42,53,67,80-88,'
ports += '135-139,389,443-445,636,'
ports += '1512,3000,3268,3269,3389,5899-5986,8080'

# Defaults and configuration stored as a dictionary
# nice for namespace management of settings and globals
_config = {
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
        'search_scope': ldap.SUBTREE,
        'search_filter': '(objectClass=computer)',
        'attributes': ldap.ALL_ATTRIBUTES,
        'tcp': {
            22:   {'name': 'ssh'},
            3389: {'name': 'ms-wbt-server'},
            5899: {'name': 'vnc'},
            },
        },
    'log': {
        'file': os.path.split(this_file)[0] + '.log',
        'level': logging.DEBUG,
        'format': "%(asctime)s: %(levelname)s: %(message)s",
        },
    }
#
# overide config with values from config file
# set the database, we dont want to initialize it until its asked for
# code in db checks if it's initialized before setting it

net_config = get_config(config_dict=_config, config_file=_config['path'])
net_db = None
net_hosts = None

@bind
def get_ip(self, d):
    """
    This method returns an tuple containing
    one or more IP address strings that respond
    as the given domain name
    """
    if isinstance(d, (list, tuple)):
        return {x:self(self,x) for x in d}
    else:
        try:
            data = socket.gethostbyname_ex(d)[2]
        except:
            data = []
        finally:
            return tuple(data)

def get_alias(d):
    """
    This method returns an array containing
    a list of aliases for the given domain
    """
    try:
        data = socket.gethostbyname_ex(d)[1]
    except Exception:
        data = []
    finally:
        return tuple(data)

def get_hostname(ip):
    """
    This method returns the 'True Host' name for a
    given IP address
    """
    try:
        data = socket.gethostbyaddr(ip)[0]
    except Exception:
        # fail gracefully
        data = None
    finally:
        return data

def sort_hosts(hosts, **kargs):
    '''Return a sorted list of ip or ranges got from adding ip
    specs to IPy.IPSet, IPSet seems to sort its list properly when iterated.
    hosts
    The list of hosts can include ip addresses, ip ranges or hostnames.
    resolve_ip
    Wether to convert ip ranges into individual ip addresses if true or
    compress individual ip addressses into ipranges if false, good
    for the nmap scan
    discard_names
    Discard hostnames - not ip addresses
    resolve_names
    Resolve hostnames into ip addresses
    '''
    resolve_ip = kargs.get('resolve_ip', True)
    discard_names = kargs.get('discard_names', False)
    resolve_names = kargs.get('resolve_names', True)

    def do_list(_ipset, _recurse=resolve_ip, _result=[]):
        for _ip in _ipset:
            if _recurse is False:
                _result.append(_ip.strNormal())
            else:
                do_list(_ip, _recurse=False, _result=_result)
        return tuple(_result)

    if isinstance(hosts, (list, tuple)): hosts = ','.join(hosts)
    if isinstance(hosts, str):
        hosts = re.sub(r'[\s,]+', ' ', hosts).strip().split()
        hosti = IPy.IPSet()
        hostd = []
        for host in hosts:
            try:
                hosti.add(IPy.IP(host))
            except:
                if discard_names is not True:
                    if resolve_names is not True:
                        hostd.append(host)
                    else:
                        for ip in get_ip(host):
                            hosti.add(IPy.IP(ip))
        hosts = do_list(hosti)
        if not discard_names is True:
            hosts += tuple(sorted(hostd))
    return(hosts)

class host():

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
        self._build = build
        self._dNSDomainName = dNSDomainName
        self._dNSHostName = dNSHostName
        self._dNSHostNames = dNSHostNames
        self._fqhn = fqhn
        self._groups = groups
        self._ipv4 = ipv4
        self._ldap = ldap
        self._name = name
        self._names = names
        self._nmap = nmap
        self._operatingSystem = operatingSystem
        self._operatingSystemVersion = operatingSystemVersion
        self._osFamily = osFamily
        self._osType = osType
        self._osVersion = osVersion
        self._tcp = tcp

    @property
    def build(self):
        return self._build

    @build.setter
    def build(self, val):
        self._build = val

    @property
    def dNSDomainName(self):
        return self._dNSDomainName

    @dNSDomainName.setter
    def dNSDomainName(self, val):
        self._dNSDomainName = val.lower()

    @property
    def dNSHostName(self):
        return self._dNSHostName

    @dNSHostName.setter
    def dNSHostName(self, val):
        self._dNSHostName = val.lower()

    @property
    def dNSHostNames(self):
        return self._dNSHostNames

    @dNSHostNames.setter
    def dNSHostNames(self, val):
        self._dNSHostNames = val

    @property
    def fqhn(self):
        return self._fqhn

    @fqhn.setter
    def fqhn(self, val):
        if isinstance(val, str):
            val = re.split(r'[\s,]+', val)
        elif isinstance(val, dict):
            val = [x['name'] for x in val if 'name' in val.keys()]
        self._fqhn = sorted(list(
            set(self._fqhn).union(
            set([x.lower() for x in val]))
        ))

    @property
    def groups(self):
        return self._groups

    @groups.setter
    def groups(self, val):
        self._groups = val

    @property
    def ipv4(self):
        return self._ipv4

    @ipv4.setter
    def ipv4(self, val):
        self._ipv4 = val

    @property
    def ldap(self):

        return self._ldap

    @ldap.setter
    def ldap(self, val):
        self._ldap = val
        if 'dNSHostName' in self._ldap.keys() and self._ldap['dNSHostName'] and not self.dNSHostName:
            self.dNSHostName = self._ldap['dNSHostName'][0]
        if 'operatingSystem' in self._ldap.keys() and self._ldap['operatingSystem']:
            self.operatingSystem = self._ldap['operatingSystem'][0]
        if 'operatingSystemVersion' in self._ldap.keys() and self._ldap['operatingSystemVersion']:
            self.operatingSystemVersion = self._ldap['operatingSystemVersion'][0]
        if self.dNSHostName and self.osFamily == 'windows':
            self.tcp = {
                22: { 'name': 'ssh' },
                3389: { 'name': 'ms-wbt-server' },
                5899: { 'name': 'vnc' }}
        if self.dNSHostName and self.osFamily == 'linux':
            self.tcp = {22: { 'name': 'ssh' }}

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, val):
        self._name = val.lower()

    @property
    def names(self):
        return self._names

    @names.setter
    def names(self, val):
        self._names = val

    @property
    def nmap(self):
        return self._nmap

    @nmap.setter
    def nmap(self, val):
        self._nmap = val
        # pprint(val)
        # wait = input("PRESS ENTER TO CONTINUE.")
        if not self._nmap[1]['scan']:
            return

        _nm = self._nmap[1]['scan'][self._nmap[0]]

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
        return self._operatingSystem

    @operatingSystem.setter
    def operatingSystem(self, operatingSystem):
        self._operatingSystem = operatingSystem
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
        return self._operatingSystemVersion

    @operatingSystemVersion.setter
    def operatingSystemVersion(self, ver):
        self._operatingSystemVersion = ver
        if ver:
            self.version = int(re.sub(r'^([0-9]+).*$', r'\1', ver))
            self.build = int(re.sub(r'^.*\(([0-9]*)\).*$', r'\1', ver))

    @property
    def osFamily(self):
        return self._osFamily

    @osFamily.setter
    def osFamily(self, val):
        self._osFamily = val.lower()

    @property
    def osType(self):
        return self._osType

    @osType.setter
    def osType(self, val):
        self._osType = val.lower()

    @property
    def osVersion(self):
        return self._osVersion

    @osVersion.setter
    def osVersion(self, val):
        if val and self.osFamily == 'windows':
            try:
                x = float(val)
            except:
                if 'xp' in val.lower():
                    self._osVersion = 5.2
                elif 'vista' in val.lower():
                    self._osVersion = 6.0
                else:
                    self._osVersion = val
            else:
                if x == 2003:
                    self._osVersion = 5.2
                elif x == 2003:
                    self._osVersion = 5.2
                elif x == 7 or x == 2008:
                    self._osVersion = 6.1
                elif x == 8:
                    self._osVersion = 6.2
                elif x == 2012:
                    self._osVersion = 6.3
                else:
                    self._osVersion = val
        else:
            self._osVersion = val

    @property
    def tcp(self):
        return self._tcp

    @tcp.setter
    def tcp(self, val):
        for k,v in val.items():
            self._tcp[k] = self._tcp.get(k, v)


class network(utils._db):
    """The network object which has as it's core a database of scan results
    from dns, ldap and nmap
    """
    def __init__(self, **a):
        self.config = get_config(
            config_dict=a.get("config", net_config),
            config_file=a.get("config_file", net_config.get("path", None))
        )
        c = self.config.get("db", {})
        c["network"] = a.get("network", c.get("network", ""))
        c["engine"] = a.get("engine", c.get("engine", "sqlite"))
        c["path"] = a.get("path", c.get("path", None))
        c["host"] = a.get("host", c.get("host", None))
        c["port"] = a.get("port", c.get("port", None))
        c["user"] = a.get("user", c.get("user", None))
        c["password"] = a.get("password", c.get("password", None))
        c["database"] = a.get("database", c.get("database", "net_db"))
        c["init"] = a.get("init", c.get("init", False))
        super().__init__(
            engine=c["engine"],
            path=c["path"],
            host=c["host"],
            port=c["port"],
            user=c["user"],
            password=c["password"],
            database=c["database"],
        )
        self.decode_json = c["engine"] != "postgres"
        if c["init"] is True:
            self.drop_tables()
        self.create_tables()
        self.hosts = self.get_hosts()
    #
    def create_tables(self, print_log=True):
        engine = self.config.get("db", {}).get("engine", "sqlite")
        def create_updated_at_trigger(table, commit=True):
            nonlocal engine
            if not table or engine == "mysql": return
            t = table + "_updated_at"
            col = "  " + ",\n  ".join(
                [x for x in self.columns(table) if x != "updated_at"]
            )
            if engine == "postgres":
                # print("creating trigger {} ...".format(t), end="", flush=True)
                self.set("DROP TRIGGER IF EXISTS {} ON {}".format(t, table))
                self.set("""
                CREATE TRIGGER {}
                BEFORE UPDATE OF
                {}
                ON {}
                FOR EACH ROW EXECUTE PROCEDURE set_timestamp()
                """.format(t, col, table), False)
                # print("done")
            elif engine == "sqlite":
                # print("creating trigger {} ...".format(t), end="", flush=True)
                self.set("DROP TRIGGER IF EXISTS {}".format(t))
                self.set("""
                CREATE TRIGGER {0}
                BEFORE UPDATE OF
                {1}
                ON {2}
                BEGIN
                    UPDATE {2}
                    SET updated_at = CURRENT_TIMESTAMP
                    WHERE id = id;
                END;
                """.format(t, col, table), False)
                # print("done")
        if engine == "postgres":
            # print("creating function set_timestamp ...", end="", flush=True)
            self.set(dedent("""
            CREATE OR REPLACE FUNCTION set_timestamp()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = NOW();
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
            """), False)
            # print("done")
        #
        i, u = "INTEGER PRIMARY KEY", ""
        if engine == "mysql":
            i = "INT PRIMARY KEY AUTO_INCREMENT"
            u = " ON UPDATE CURRENT_TIMESTAMP"
        elif engine == "postgres":
            i = "serial PRIMARY KEY"
        #
        table = "network"
        sql = """
        CREATE TABLE {} (
            id {},
            name VARCHAR(64) NOT NULL DEFAULT '',
            config JSON,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP{},
            UNIQUE (name)
        ); """.format("{0}",i, u)
        res = self.create_table(table, sql, commit=False, print_log=print_log)
        create_updated_at_trigger(table, commit=False)
        #
        table = "host"
        sql = """
        CREATE TABLE {} (
            id {},
            network_id INTEGER,
            name VARCHAR(64),
            data JSON,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP{},
            UNIQUE (network_id, name),
            FOREIGN KEY (network_id) REFERENCES network(id)
                ON DELETE CASCADE
        ); """.format("{0}", i, u)
        res = self.create_table(table, sql, commit=False, print_log=print_log)
        create_updated_at_trigger(table, commit=False)
        #
        table = "dns"
        sql = """
        CREATE TABLE {} (
            id {},
            network_id INTEGER,
            server VARCHAR(64) NOT NULL,
            data JSON,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP{},
            FOREIGN KEY (network_id) REFERENCES network(id)
                ON DELETE CASCADE
        );""".format("{0}", i, u)
        res = self.create_table(table, sql, commit=False, print_log=print_log)
        create_updated_at_trigger(table, commit=False)
        #
        table = "ldap"
        sql = """
        CREATE TABLE {} (
            id {},
            network_id INTEGER,
            server VARCHAR(64) NOT NULL,
            search_base VARCHAR(255) NOT NULL,
            search_filter VARCHAR(255) NOT NULL,
            attributes VARCHAR(255) NOT NULL,
            data JSON NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP{},
            FOREIGN KEY (network_id) REFERENCES network(id)
                ON DELETE CASCADE
        ); """.format("{0}", i, u)
        res = self.create_table(table, sql, commit=False, print_log=print_log)
        create_updated_at_trigger(table, commit=False)
        #
        table = "nmap"
        sql = """
        CREATE TABLE {} (
            id {},
            network_id INTEGER,
            host VARCHAR(64) NOT NULL,
            ports VARCHAR(255) NOT NULL DEFAULT '',
            arguments VARCHAR(255) NOT NULL DEFAULT '',
            command_line VARCHAR(255) NOT NULL DEFAULT '',
            data JSON NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP{},
            FOREIGN KEY (network_id) REFERENCES network(id)
                ON DELETE CASCADE
        );""".format("{0}", i, u)
        res = self.create_table(table, sql, commit=False, print_log=print_log)
        create_updated_at_trigger(table, commit=False)
        #
        self.connection.commit()

    @staticmethod
    def sort_nmap_ports(ports):
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

    @staticmethod
    def sort_nmap_arguments(arguments):
        if isinstance(arguments, list):
            arguments = [re.sub(r"^(\s*-\s*)+", "", x) for x in arguments]
        else: arguments = arguments.split("-")
        arguments = [x.strip() for x in arguments if x]
        arguments.sort()
        arguments = ["-" + x for x in arguments]
        arguments = " ".join(arguments)
        return arguments

    def get_table(self, table, **kargs):
        """Generic select statement for known tables

        if a field column named data is included in the select, then it
        is assumed to be json encoded and decoded if neccessary
        postgres 11 does not require decoding maybe previous versions do

        The table must have a field called updated_at, if current is True,
        then only return records that have been updated in the last number
        of days given by the days parameter

        if fetchall is True it returns all records in a list of tuples
        if fetchall is False it returns a single record as a tuple
        the default for fetchall is False

        criteria is an optional dict of {column: value} to be used in the
        where clause of the select statement, if any of the values is a list
        or tuple, then a 'WHERE column IN ()' is used if not a
        'WHERE column =' is used

        columns is an optional list of columns for the select statement
        can be a comma or space separated string or a list or tuple of
        strings if not specified, '*' (all columns) is assumed
        """
        config = self.config.get(table, {})
        fetchall = kargs.get("fetchall", False)
        show = kargs.get("show", False)
        current = kargs.get("current", True)
        columns = kargs.get("columns", "*")
        criteria = kargs.get("criteria", {})
        defaults = kargs.get("defaults", ())
        days = kargs.get("days", None) or config.get("days", None)
        if fetchall is False:
            for i in defaults:
                criteria[i] = kargs.get(i, None) or config.get(i, None)
        else:
            for i in defaults:
                criteria[i] = kargs.get(i, None)
        network = config.get("network", None)
        # pprint(criteria)
        if isinstance(columns, str):
            columns = re.split(r"[\s,]+", columns)
        columns = ["n.name" if x == "network" else "t." + x for x in columns]
        columns = ", ".join(columns)
        sql = [
            ["n.name {} {}".format("=" if network else "IS", self.p)],
            [network]
        ]
        if days and current is True:
            sql[0].append("t.updated_at > " + self.p)
            sql[1].append(datetime.now() - timedelta(days=int(days)))
        if criteria:
            for k,v in criteria.items():
                if v:
                    if isinstance(v, list) or isinstance(v, tuple):
                        sql[0].append("{} IN ({})".format(
                            "t." + k, ", ".join([self.p] * len(v))))
                        if isinstance(v, tuple):
                            sql[1] += list(v)
                        else:
                            sql[1] += v
                    else:
                        sql[0].append("{} = {}".format("t." + k, self.p))
                        sql[1].append(v)
        if sql[0]:
            sql[0] = " WHERE " + " AND ".join(sql[0])
        else:
            sql[0] = ""

        sql[0] = """
        SELECT {}
        FROM {} AS t
        JOIN network AS n ON t.network_id = n.id
        {}
        ORDER BY t.updated_at DESC
        {};""".format(
            columns, table, sql[0],
            "LIMIT 1" if not fetchall is True else "",
        )
        r = self.get(sql=sql, fetchall=fetchall, show=show)
        c = [x[0] for x in self.cursor.description]
        if self.decode_json is False: return r
        def d(t, c):
            r = ()
            for x in range(len(t)):
                if c[x] in ("data","config"): r += (json.loads(t[x]),)
                else: r += (t[x],)
            return r
        if not r:
            return r
        if fetchall == True:
            return [d(x, c) for x in r]
        else:
            return d(r, c)

    def encode_ldap_attributes(self, s):
        if isinstance(s, str):
            return json.dumps([s])
        elif isinstance(s, (list, tuple)):
            return json.dumps(list(s))

    def decode_ldap_attributes(self, s):
            return json.loads(s)

    def get_network(self, network=None, commit=True):
        c = self.config.get("db", {})
        network = network or c.get("network", None)
        engine = c.get("engine", None)
        self.cursor.execute(
            "SELECT * FROM network WHERE name = {}".format(self.p),
            (network,)
        )
        result = self.cursor.fetchone()
        if not result:
            self.cursor.execute("""
            INSERT INTO network (name, config) VALUES ({0}, {0}){1}
            """.format(
                self.p,
                " RETURNING *" if self.engine == "postgres" else "",
            ), (
                network,
                json.dumps(self.config),
            ))
            if engine == "postgres":
                result = self.cursor.fetchone()
                if commit is not False: self.connection.commit()
            else:
                if commit is not False: self.connection.commit()
                result = self.get_network()
        return result

    def set_network(self, network=None, commit=True):
        c = self.config.get("db", {})
        network = network or c.get("network", None)
        self.cursor.execute(
            "SELECT * FROM network WHERE name = {}".format(self.p),
            (network,)
        )
        result = self.cursor.fetchone()
        if not result:
            self.cursor.execute("""
            INSERT INTO network (name, config) VALUES ({0}, {0})
            """.format(self.p,), (
                network,
                json.dumps(self.config),
            ))
        else:
            self.cursor.execute("""
            UPDATE network SET name = {0}, config = {0} WHERE id = {0}
            """.format(self.p,), (
                network,
                json.dumps(self.config),
                result[0]
            ))
        if commit is not False: self.connection.commit()

    def get_hosts(self):
        """Read host objects stored in the database as serialized json
        into a dict of host objects
        """
        def dto(h):
            """Convert a dict to a new host object
            """
            r = host()
            for k, v in h.items(): setattr(r, k, v)
            return r
            #
        r = self.get_table("host", columns="name, data",
                           fetchall=True, current=False,)
        return {x[0]: dto(x[1]) for x in r} if r else {}

    def get_dns(self, **a):
        a["table"] = "dns"
        config = self.config.get(a["table"], None)
        a["network"] = a.get("network", config.get("network", None))
        a["server"] = a.get("server", config.get("server", None))
        a["days"] = a.get("days", config.get("days", None))
        a["defaults"] = ("server",)
        return self.get_table(**a)

    def get_ldap(self, **a):
        a["table"] = "ldap"
        config = self.config.get(a["table"], None)
        a["network"] = a.get("network", config.get("network", None))
        a["days"] = a.get("days", config.get("days", None))
        a["columns"] = a.get("columns", None)
        a["criteria"] = {
            "server": a.get("server", config.get("server", None)),
            "search_base": a.get("search_base", config.get("search_base", None)),
            "search_filter": a.get("search_filter", config.get("search_filter", None)),
            "attributes": a.get("attributes", config.get("attributes", None)),
        }
        return self.get_table(**a)

    def get_nmap(self, **a):
        a["table"] = "nmap"
        config = self.config.get(a["table"], None)
        a["network"] = a.get("network", config.get("network", None))
        a["days"] = a.get("days", config.get("days", None))
        a["columns"] = a.get("columns", None)
        a["criteria"] = {
            "hosts": a.get("hosts", config.get("ip_range", None)),
            "ports": a.get("ports", config.get("ports", None)),
            "arguments": a.get("arguments", config.get("arguments", None)),
        }
        return self.get_table(**a)
    #
    def set_hosts(self, hosts=None):
        """
        hosts is a dictionary of type
        { string: object }
        """
        conf = self.config("db", {})
        hosts = hosts or self.hosts
        hosts = {k: json.dumps(v.__dict__) for k, v in hosts.items()}
        if not hosts:
            return
        names = [k for k, v in hosts.items()]
        if conf.get("engine", None) == "mysql":
            d = "ON DUPLICATE KEY UPDATE"
        else:
            d = "ON CONFLICT (network_id, name) DO UPDATE SET"
        network_id = self.get_network(commit=False)[0]
        for k, v in hosts.items():
            sql = ("""
                INSERT INTO host (network_id, name, data)
                VALUES ({0}, {0}, {0})
                {1}
                data = {0}""".format(self.p, d), (network_id, k, v, v)
            )
            self.set(sql, commit=False)
        sql = ("""
            DELETE FROM host WHERE network_id = {}
            AND name NOT IN ({})
            """.format(self.p, ', '.join([self.p] * len(names))),
            (network_id,) + tuple(names)
        )
        self.set(sql, commit=False)
        self.connection.commit()

    def set_dns(self, **k):
        conf = self.config("dns", {})
        server = k.get("server", conf.get("server", None))
        network = k.get("network", conf.get("network", None))
        network_id = self.get_network(network=network, commit=False)[0]
        data = k.get("data", None)
        if not data:
            return
        sql = ("""
            INSERT INTO dns (network_id, server, data)
            VALUES ({0}, {0}, {0})""".format(self.p),
            (network_id, server, json.dumps(data)))
        self.set(sql, commit=False)
        self.connection.commit()

    def set_nmap(self, host=None, ports=None, arguments=None,
                            command_line=None, data=None, **kargs):
        section = "nmap"
        config = get_config(section,
            config_dict=kargs.get("config", net_config.get(section, {})),
            config_file=kargs.get("config_file", net_config.get("path", None)))
        if not (host and data): return
        network_id = self.get_network(commit=False)
        sql = [["network_id"], [network_id]]
        if host:
            host = host.strip().lower()
            sql[0].append("host")
            sql[1].append(host)
        if ports:
            ports = self.sort_nmap_ports(ports)
            sql[0].append("ports")
            sql[1].append(ports)
        if arguments:
            arguments = self.sort_nmap_arguments(arguments)
            sql[0].append("arguments")
            sql[1].append(arguments)
        if command_line:
            sql[0].append("command_line")
            sql[1].append(command_line)
        sql[0].append("data")
        sql[1].append(json.dumps(data))
        sql[0] = "INSERT INTO {} ({}) VALUES ({});".format(
            section, ", ".join(sql[0]), ", ".join([self.p] * len(sql[0])))
        self.set(sql, commit=False)
        self.connection.commit()


    def set_ldap(self, **kargs,):
        section = "ldap"
        config = get_config(
            config_section=section,
            config_dict=kargs.get("config", net_config.get(section, {})),
            config_file=kargs.get("config_file", net_config.get("path", None))
        )
        def get_var(v,d=None):
            return kargs.get(v, None) or config.get(v, d)
        network = get_var("network")
        server = get_var("server")
        search_base = get_var("search_base")
        search_filter = get_var("search_filter")
        attributes = get_var("attributes")
        data = get_var("data")
        commit = get_var("commit")
        if not (server and data and (
            search_base or search_filter or attributes)):
            return
        network_id = self.get_network(commit=False)[0]
        sql = [["network_id"], [network_id]]
        sql[0].append("server")
        sql[1].append(server)
        if search_base:
            sql[0].append("search_base")
            sql[1].append(search_base)
        if search_filter:
            sql[0].append("search_filter")
            sql[1].append(search_filter)
        if attributes:
            sql[0].append("attributes")
            sql[1].append(self.encode_ldap_attributes(attributes))
        sql[0].append("data")
        sql[1].append(json.dumps(data))
        sql[0] = "INSERT INTO {} ({}) VALUES ({});".format(
            section, ", ".join(sql[0]), ", ".join([self.p] * len(sql[0])))
        # pprint(sql[1][:-1])
        self.set(sql, commit=False)
        self.connection.commit()


def host_list(*args):
    hostd = []
    hosti = ip.IPSet()
    for arg in args:
        ar = arg
        if isinstance(ar, str):
            ar = re.sub(r'\n', ' ', ar)
            ar = re.split(r'[\s,]+', ar)
        for a in ar:
            try:
                hosti.add(ip.IP(a))
            except:
                hostd.append(a)

    res = [x.strNormal() for x in hosti] + sorted(hostd)
    res = ' '.join(res)
    return (hosti.len() + len(hostd), res)


def combine_hosts(*args):
    hostd = []
    hosti = ip.IPSet()
    for arg in args:
        ar = arg
        if isinstance(ar, str):
            ar = re.sub(r'\n', ' ', ar)
            ar = re.split(r'[\s,]+', ar)
        for a in ar:
            try:
                hosti.add(ip.IP(a))
            except:
                hostd.append(a)
    res = [x.strNormal() for x in hosti] + sorted(hostd)
    res = ' '.join(res)
    return res


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

    res = [x.strNormal() for x in res]
    res = ' '.join(res)

    return res


def json_hosts_dict(hosts_dict):
    result = {k:v.__dict__ for k,v in hosts_dict.items()}
    return result



def dns_search(**kargs):
    global net_db
    global net_hosts
    global net_config
    config = get_config(
        config_section="dns",
        config_dict=kargs.get("config", net_config),
        config_file=kargs.get("config_file", net_config.get("path", None)),
    )
    def get_var(v,d=None):
        return kargs.get(v, None) or config.get(v, d)
    server = get_var("server")
    domain = get_var("domain")
    user = get_var("user")
    password = get_var("password")
    days = get_var("days")
    network = get_var("network")
    save_hosts = get_var("save_hosts", True)
    username = domain + '\\' + user if domain else user
    db = kargs.get('db', None) or _db(set_hosts=True, db=net_db)
    hostsd = kargs.get('hostsd', net_hosts)
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
        try:
            stdout, stderr, rc = dns_client.execute_ps(ps)
        except Exception as e:
            print('failed')
            print(e)
            # print(sys.exc_info()[1])
            # print(stderr)
            return [], e
        res = [x.split() for x in stdout.split('\n') if x][2:]
        res = sorted([[x[0], (x[1] + '.' + x[2]).lower()] for x in res])
        res = itertools.groupby(res, lambda x: x[0])
        res = [[k,[x[1] for x in list(v)]] for k,v in res]
        res = [[IPy.IP(x[0]).int(), x[0], x[1]] for x in res]
        res = [x[1:] for x in sorted(res)]
        return res, None
    #
    res = db.get_dns(server=server, columns=("data"), days=days)
    if res:
        print("read cached dns {}".format(server))
        res = res[0]
    else:
        print("searching dns {} ...".format(server), end="", flush=True)
        res = search()
        if res[1]:
            print("failed")
            res = db.get_dns(server=server, columns=("data"))
            if res:
                print("could not query server {} read cached".format(server))
                res = res[0]
            else:
                print("could not query server {}".format(server))
                res = None
        else:
            print("done")
            res = res[0]
        if res:
            print("saving dns search {} ..."
                  .format(server), end="", flush=True)
            db.set_dns(server, res)
            print("done")
    # print(res)
    for s in res:
        f = None
        for n in s[1]:
            if n in hostsd.keys():
                f = n
                break
            if not f:
                for k,v in hostsd.items():
                    if n in v.fqhn:
                        f = k
                        break
        if not f:
            f = sorted(s[1])[0]
            hostsd[f] = host()
        hostsd[f].ipv4 = s[0]
        hostsd[f].fqhn = s[1]
    if save_hosts is True:
        db.set_hosts(hostsd)

def ldap_search(**k):
    global net_db
    global net_hosts
    global net_config
    config = get_config(
        config_section="ldap",
        config_dict=k.get("config", None) or net_config,
        config_file=k.get("config_file", None) or net_config.get("path", None),
    )
    def get_var(v):
        return k.get(v, None) or config.get(v, None)
    server = get_var("server")
    fqdn = get_var("fqdn")
    domain = get_var("domain")
    user = get_var("user")
    password = get_var("password")
    days = get_var("days")
    network = get_var("network")
    search_scope = get_var("search_scope")
    search_filter = get_var("search_filter")
    attributes = get_var("attributes")
    save_hosts = get_var("save_hosts")

    username = domain + "\\" + user if domain else user
    db = k.get("db", net_db) or _db(set_hosts=True, db=net_db)
    hostsd = k.get("hostsd", net_hosts)
    search_base = ",".join(["dc=" + x for x in fqdn.split(".")])

    # pprint(config)
    # pprint(server)
    # pprint(search_base)
    # pprint(search_filter)
    # pprint(search_scope)
    # pprint(type(attributes))

    # return

    # search_scope = ldap.SUBTREE
    # search_filter ='(objectClass=computer)'
    # attributes = ldap.ALL_ATTRIBUTES

    conn = None

    def search(
        server=server,
        search_base=search_base,
        search_filter=search_filter,
        attributes=attributes,
        days=days,):

        args = locals()
        nonlocal conn
        res = db.get_ldap(
            server=server,
            search_base=search_base,
            search_filter=search_filter,
            attributes=attributes,
            columns=("data",),
            days=days,)
        if res:
            print("read cached ldap {} {}".format(server, search_filter))
            res = res[0]
        else:
            if not conn:
                try:
                    print("connecting to ldap server {} ...".format(server),
                          end="", flush=True)
                    conn = ldap.Connection(
                        server="ldap://" + server,
                        user=username,
                        password=password,
                        authentication=ldap.NTLM,
                        auto_bind=True,
                    )
                    print("done")
                except Exception as e:
                    print("failed")
                    print(e)
                    res = [], e
            if conn:
                print("search ldap {} {} ...".format(server, search_filter),
                end="", flush=True)
                try:
                    conn.search(
                        search_base=search_base,
                        search_scope=search_scope,
                        search_filter=search_filter,
                        attributes=attributes,
                    )
                except Exception as e:
                    print("failed")
                    print(e)
                    res = [], e
                # beacause of a couple of datetime fields in the output
                # we have to use the ldap3 lib to convert the entry to json
                # then use json lib to bring it back to dict
                res = [json.loads(x.entry_to_json()) for x in conn.entries], None
            if res[1]:
                print("failed")
                res = db.get_ldap(
                    server=server,
                    search_base=search_base,
                    search_filter=search_filter,
                    attributes=attributes,
                    columns=("data",),
                )
                if res:
                    print("could not query server {} read cached".format(server))
                    res = res[0]
                else:
                    print("could not query server {}".format(server))
                    res = None
            else:
                print("done")
                res = res[0]
            if res:
                print("saving ldap {} {} ...".format(server, search_filter),
                    end="", flush=True)
                db.set_ldap(
                    server=server,
                    search_base=search_base,
                    search_filter=search_filter,
                    attributes=attributes,
                    data=res
                )
                print("done")
        return res

    # pprint(attributes)

    groups = search(search_filter='(objectClass=group)', attributes=['name', 'member'])
    groups = [[x['attributes']['name'][0], x['attributes']['member'],] for x in groups]
    res = search(search_filter='(objectClass=computer)', attributes=['*'])
    for s in res:
        if 'objectClass' in s['attributes'].keys() and (
            'computer' in s['attributes']['objectClass']):
            n = s['attributes']['name'][0]
            n = (n + '.' + fqdn).lower()
            f = None
            if n in hostsd.keys():
                f = n
            else:
                for k,v in hostsd.items():
                    for x in v.fqhn:
                        if n == x:
                            hostsd[n] = hostsd[k]
                            f = n
                            break
                    if f:
                        del hostsd[k]
                        break
            if not f:
                f = n
                hostsd[f] = host()
            hostsd[f].ldap = s['attributes']
            hostsd[f].groups = [x[0] for
            x in groups if s['attributes']['distinguishedName'][0] in x[1]]

#    return hostsd
#
#
#def nmap_scan(hosts=None, fqdn=None, ip_range=None, days=None,
#    ports=None, arguments=None,
#    config_file=config['path'], config=None,
#    db=net_db, host_dict={},
#    scan_connected=False, scan_ip_range=False,
#    ):
#
#    global net_db
#    if not db:
#        if not net_db:
#            net_db = db()
#        db = net_db
#
#    if not config:
#        config=globals()['config']['nmap']
#    if 'nmap' in config.keys() and isinstance(config['nmap'], dict):
#        config=config['nmap']
#
#    if config_file and os.path.isfile(config_file):
#        parser.read(config_file)
#        config.update({k:v for k,v in parser['nmap'].items() if v})
#
#    if not hosts:
#        hosts = combine_hosts(
#            [v.ipv4 if v.ipv4 else k for k,v in host_dict.items()]
#        )
#    if scan_connected is True:
#        hosts = combine_hosts(hosts, connected_networks())
#    if scan_ip_range is True:
#        hosts = combine_hosts(hosts, ip_range)
#
#    if not hosts or hosts == '':
#        return
#
#    fqdn = config.get('fqdn') if not fqdn else fqdn
#    ip_range = config.get('ip_range') if not ip_range else ip_range
#    days = config.get('days') if not days else days
#    ports = config.get('ports') if not ports else ports
#    arguments = config.get('arguments') if not arguments else arguments
#
#    output = {}
#
#    def set_dict(ip, result):
#        if 'scan' not in result.keys():
#            return
#        f = None
#        for k,v in host_dict.items():
#            if v.ipv4 and v.ipv4 == ip:
#                f = k
#                break
#        if not f:
#            s = result['scan'][ip]
#            if 'hostnames' in s.keys():
#                for h in s['hostnames']:
#                    if h['name'] in host_dict.keys():
#                        f = h['name']
#                        break
#                if not f:
#                    f = s['hostnames'][0]['name']
#                    host_dict[f] = host()
#        if not f:
#            f = ip
#            host_dict[f] = host()
#        host_dict[f].nmap = [ip, result]
#        output[f] = host_dict[f]
#
#    def save_entry(ip, result):
#        if not result['scan']:
#            return
#        if db:
#            cmd = result['nmap']['command_line']
#            set_nmap(db=db,
#                host=ip, ports=ports, arguments=arguments,
#                command_line=cmd, data=[ip, result])
#            print('\nsaved  : {}'.format(cmd))
#        set_dict(ip, result)
#
#
#    print('nmap scan ....')
#    ps = nmap.PortScanner()
#    psa = nmap.PortScannerAsync()
#
#    l, hosts = host_list(hosts)
#    print('ping {} ....'.format(
#        hosts if l < 2 else 'sweep ' + str(l) + ' hosts'
#    ), end='', flush=True)
#    # ps.scan(hosts, arguments='-n -sn -PE -PA22,23,80', sudo=True)
#    ps.scan(hosts, arguments=config['ping'], sudo=True)
#    hosts = ps.all_hosts()
#    l = len(hosts)
#    ls = '1 host' if l == 1 else str(l) + ' hosts'
#    print('done. Found {}'.format(ls))
#    print('searching database for {} ...'.format(ls), end='', flush=True)
#    results = get_nmap(db=db,
#        hosts=hosts,
#        ports=ports,
#        arguments=arguments,
#        fetchall=True,
#        days=days,
#    )
#    l = len(results)
#    ls = '1 host' if l == 1 else str(l) + ' hosts'
#    print('done. Found {}'.format(ls))
#
#    if results:
#        hostd = [x[1] for x in results]
#        hosts = [x for x in hosts if x not in hostd]
#        for result in results:
#            if not result[5][1]['scan']:
#                hosts.append(result[0])
#                continue
#            print('read   : {}'.format(result[4]))
#            set_dict(result[5][0], result[5][1])
#
#    hosts = self.sort_name_hosts(hosts)
#    ports = self.sort_nmap_ports(ports)
#    arguments = self.sort_nmap_arguments(arguments)
#
#    if hosts:
#        psa = nmap.PortScannerAsync()
#        l, hosts = host_list(hosts)
#        ls = '1 host' if l == 1 else str(l) + ' hosts'
#        print('scanning {}'.format(ls))
#        print("Waiting for nmap ....")
#        psa.scan(
#            hosts=hosts,
#            ports=ports,
#            arguments=arguments,
#            callback=save_entry,
#            sudo=True,
#            )
#        while psa.still_scanning():
#            print('.', end='', flush=True)
#            psa.wait(10)
#
#    print('nmap scan done')
#    return host_dict
#
#
#def hosts_dict(
#    arguments=None,
#    days=None,
#    domain=None,
#    fqdn=None,
#    hosts=None,
#    ip_range=None,
#    password=None,
#    ports=None,
#    server=None,
#    user=None,
#    scan_connected=False,
#    scan_ip_range=False,
#    dns_days=None,
#    dns_domain=None,
#    dns_password=None,
#    dns_server=None,
#    dns_user=None,
#    ldap_days=None,
#    ldap_domain=None,
#    ldap_fqdn=None,
#    ldap_password=None,
#    ldap_server=None,
#    ldap_user=None,
#    nmap_arguments=None,
#    nmap_days=None,
#    nmap_fqdn=None,
#    nmap_hosts=None,
#    nmap_ip_range=None,
#    nmap_ports=None,
#    config_file=config['path'], config={},
#    db=None, host_dict={},
#    ):
#
#    global net_db
#    if not db:
#        if not net_db:
#            net_db = db()
#        db = net_db
#
#    if not config:
#        config=globals()['config']
#
#    if config_file and os.path.isfile(config_file):
#        parser.read(config_file)
#        mergeConf(config, {
#            k: dict(parser.items(k))
#            for k in parser.sections()
#        })
#
#    if not dns_server: dns_server = server if server else config.get('dns', {}).get('server', None)
#    if not dns_user: dns_user = user if user else config.get('dns', {}).get('user', None)
#    if not dns_domain: dns_domain = domain if domain else config.get('dns', {}).get('domain', None)
#    if not dns_password: dns_password = password if password else config.get('dns', {}).get('password', None)
#    if not dns_days: dns_days = days if days else config.get('dns', {}).get('days', None)
#
#    if not ldap_server: ldap_server = server if server else config.get('ldap', {}).get('server', None)
#    if not ldap_fqdn: ldap_fqdn = fqdn if fqdn else config.get('ldap', {}).get('fqdn', None)
#    if not ldap_user: ldap_user = user if user else config.get('ldap', {}).get('user', None)
#    if not ldap_domain: ldap_domain = domain if domain else config.get('ldap', {}).get('domain', None)
#    if not ldap_password: ldap_password = password if password else config.get('ldap', {}).get('password', None)
#    if not ldap_days: ldap_days = days if days else config.get('ldap', {}).get('days', None)
#
#    if not nmap_hosts: nmap_hosts = hosts if hosts else config.get('nmap', {}).get('hosts', None)
#    if not nmap_fqdn: nmap_fqdn = fqdn if fqdn else config.get('nmap', {}).get('fqdn', None)
#    if not nmap_ip_range: nmap_ip_range = ip_range if ip_range else config.get('nmap', {}).get('ip_range', None)
#    if not nmap_days: nmap_days = days if days else config.get('nmap', {}).get('days', None)
#    if not nmap_ports: nmap_ports = ports if ports else config.get('nmap', {}).get('ports', None)
#    if not nmap_arguments: nmap_arguments = arguments if arguments else config.get('nmap', {}).get('arguments', None)
#
#    dns_search(
#        server=dns_server,
#        user=dns_user,
#        domain=dns_domain,
#        password=dns_password,
#        days=dns_days,
#        db=db,
#        host_dict=host_dict,
#    )
#
#    ldap_search(
#        server=ldap_server,
#        fqdn=ldap_fqdn,
#        domain=ldap_domain,
#        user=ldap_user,
#        password=ldap_password,
#        days=ldap_days,
#        db=db,
#        host_dict=host_dict,
#    )
#
#    nmap_scan(
#        hosts=nmap_hosts,
#        fqdn=nmap_fqdn,
#        ip_range=nmap_ip_range,
#        days=nmap_days,
#        ports=nmap_ports,
#        arguments=nmap_arguments,
#        db=db,
#        scan_connected=scan_connected,
#        scan_ip_range=scan_ip_range,
#        host_dict=host_dict,
#    )
#
#    return host_dict
#

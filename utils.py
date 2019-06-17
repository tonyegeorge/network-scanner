
import sys
import os
import re
import copy
import itertools
import warnings
import inspect
import configparser
import logging
import sqlparse
import psycopg2 as postgres
import pymysql  as mysql
import sqlite3  as sqlite
from pprint import pprint
#

def dedent(s):
    """dedent a multiline string by the indent of the first line
    """
    m = re.match(r"\s+", s)
    if not m:
        return s.strip()
    m =  re.sub(r"\n", "", m[0])
    return re.sub(r"\n{}".format(m), "\n", s).strip()

def bind(f):
    """Decorate function `f` to pass a reference to the function
    as the first argument"""
    return f.__get__(f, type(f))
#
@bind
def strip(self, t):
    '''Strips newlines and extra spaces from string
    '''
    if isinstance(t, str):
        # remove extra spaces, tabs and newlines
        # remove spaces after opening parenthesis
        # and spaces before closing parenthesis
        return  ' '.join(t.split()).replace('( ', '(').replace(' )', ')')
    if isinstance(text, list):
        return [self(self,x) for x in t]
    if isinstance(text, tuple):
        return tuple(self(self,x) for x in t)
    if isinstance(t, dict):
        return {self(self,k):self(self,v) for k,v in t.items()}
    else:
        return t
#
def find_parentheses(s):
    """ Find and return the location of the matching parentheses pairs in s.
    Given a string, s, return a dictionary of start: end pairs giving the
    indexes of the matching parentheses in s. Suitable exceptions are
    raised if s contains unbalanced parentheses.
    """
    # The indexes of the open parentheses are stored in a stack, implemented
    # as a list
    stack = []
    parentheses_locs = {}
    for i, c in enumerate(s):
        if c == '(':
            stack.append(i)

        elif c == ')':
            try:
                parentheses_locs[stack.pop()] = i
            except IndexError:
                raise IndexError('Too many close parentheses at index {}'
                    .format(i))
    if stack:
        raise IndexError('No matching close parenthesis to open parenthesis '
                         'at index {}'.format(stack.pop()))
    return parentheses_locs
#
def parse_sql_create_table(sql, last_column='updated_at'):
    '''Returns table and list of columns from sql create table statement
    on the condition that the last column is specified by the last_column
    parameter
    '''
    regex = '^(CREATE ((GLOBAL |LOCAL )?(TEMPORARY |TEMP )?|UNLOGGED )?'
    regex += 'TABLE (IF (NOT )?EXISTS )?)'
    regex = re.compile(regex, re.IGNORECASE)
    res = regex.sub('', strip(sql))
    res = [res.split()[0].split('.')[-1], ' '.join(res.split()[1:])]
    res[1] = res[1][1:find_parentheses(res[1])[0]].split(',')
    columns = []
    for column in res[1]:
        column = column.split()[0].strip()
        columns.append(column)
        if column == last_column:
            break
    return res[0], columns
#
def get_config(**kargs):
    '''Returns a new configuration dict from a new or existing dict updated
    with values read from an ini style configuration file using configParser
    '''
    config_section = kargs.get('config_section', None)
    config_dict = kargs.get('config_dict', {})
    config_file = kargs.get('config_file', None)
    #
    if config_section and config_dict and config_section in config_dict.keys()\
    and isinstance(config_dict[config_section], dict):
        config_dict = config_dict.get(config_section)
    #
    # print(config_dict)
    if config_file:
        if os.path.isfile(config_file):
            parser = configparser.ConfigParser()
            parser.read(config_file)
        else:
            print('The file {} does not exist ... exiting.'.format(config_file))
            sys.exit()
        if not config_section:
            for sect in parser.sections():
                config_dict[sect] = get_config(
                    config_section=sect,
                    config_dict=config_dict.get(sect, {}),
                    config_file=config_file,)
        else:
            if config_section in parser.sections():
                config_dict.update(
                    {k:v for k,v in parser[config_section].items() if v})
    return config_dict
#
utils_db = None
class _db():
    '''A generic database class with some common functions
    supports mysql, postgres or sqlite

    ** mysql **
    CREATE DATABASE net_db;
    CREATE USER 'net_db'@'%' IDENTIFIED WITH mysql_native_password BY 'net_db';
    CREATE USER 'net_db'@'localhost' IDENTIFIED WITH mysql_native_password BY 'net_db';
    GRANT ALL PRIVILEGES ON net_db.* TO 'net_db'@'%';
    GRANT ALL PRIVILEGES ON net_db.* TO 'net_db'@'localhost';

    To allow network access
    in my.cnf or mysqld.conf whichever is applicable to your platform,
    locate this line
        bind-address   = 127.0.0.1
    and cahnge to
        bind-address   = 0.0.0.0
    or any address you want on the system

    ** postgres **
    create database net_db;
    create user net_db with encrypted password 'net_db';
    grant all privileges on database net_db to net_db;

    To allow network access
    By default, PostgreSQL DB server listen address is set to the
    'localhost' , and we need to change it so it accepts connection from
    any IP address; or you can use comma separated list of addresses.
    Open
        postgresql.conf
    search for listen_addresses , and set it to '*' :
        listen_addresses = '*'
    or if you want to set connection restrictions to a few IP’s, then
    you should set listen_addresses  to something like this:
    listen_addresses = '192.168.1.100,192.168.1.101,192.168.1.110'

    To allow connections from absolutely any address with password
    authentication Open
        pg_hba.conf
    add this line at the end of pg_hba.conf
        host all all 0.0.0.0/0 md5
    You can also use your network/mask instead of just 0.0.0.0/0

    '''
    def __init__(self, **kargs):
        self.engine = kargs.get('engine', None)
        self.path = kargs.get('path', None)
        self.host = kargs.get('host', None)
        self.port = kargs.get('port', None)
        self.user = kargs.get('user', None)
        self.password = kargs.get('password', None)
        self.database = kargs.get('database', None)
        self.connect()
        self.sql = None
        self.data = None
    #
    def default_port(self):
        if self.engine == 'mysql':
            return 3306
        elif self.engine == 'postgres':
            return 5432
        else:
            return None
    #
    @property
    def port(self):
        return self._port or self.default_port()
    #
    @port.setter
    def port(self, val):
        if isinstance(val, (str,int)):
            try:
                self._port = int(val)
            except:
                self._port = None
        else:
            self._port = None
    #
    @property
    def sql(self):
        return self._sql
    #
    @sql.setter
    def sql(self, val):
        if isinstance(val, str):
            self._sql = strip(val)
        elif isinstance(val, (list, tuple)):
            if val[0] and isinstance(val[0], str):
                self._sql = strip(val[0]), val[1]
            else:
                self._sql = None
        else:
            self._sql = None
    #
    def connect(self, **kargs):
        global utils_db
        # print(utils_db)
        # print('globals {}'.format(utils_db))
        self.engine = kargs.get('engine', self.engine)
        self.path = kargs.get('path', self.path)
        self.host = kargs.get('host', self.host)
        self.port = kargs.get('port', self.port)
        self.user = kargs.get('user', self.user)
        self.password = kargs.get('password', self.password)
        self.database = kargs.get('database', self.database)
        #
        if self.engine == 'mysql':
            self.p = '%s'
            if utils_db and isinstance(utils_db, _db) and\
            utils_db.engine == self.engine and\
            utils_db.host == self.host and\
            utils_db.port == self.port and\
            utils_db.user == self.user and\
            utils_db.password == self.password and\
            utils_db.database == self.database and\
            utils_db.connection:
                print('database already open')
                self.connection = utils_db.connection
                self.cursor = utils_db.cursor or utils_db.connection.cursor()
            else:
                print('connecting to {} {} ...'.format(
                    self.engine, self.database), end='', flush=True)
                try:
                    self.connection = mysql.connect(
                        host=self.host,
                        port=self.port,
                        user=self.user,
                        password=self.password,
                        database=self.database,)
                except mysql.Error as e:
                    print('failed mysql connection error')
                    print("Error %d: %s" % (e.args[0], e.args[1]))
                    self.connection = None
                    sys.exit()
                else:
                    print('done')
                self.cursor = self.connection.cursor()
                if utils_db and isinstance(utils_db, _db):
                    try:
                        utils_db.connection.close()
                    except:
                        pass
                utils_db = self
        #
        elif self.engine == 'postgres':
            self.p = '%s'
            if utils_db and isinstance(utils_db, _db) and\
            utils_db.engine == self.engine and\
            utils_db.host == self.host and\
            utils_db.port == self.port and\
            utils_db.user == self.user and\
            utils_db.password == self.password and\
            utils_db.database == self.database and\
            utils_db.connection:
                print('database already open')
                self.connection = utils_db.connection
                self.cursor = utils_db.cursor or utils_db.connection.cursor()
            else:
                print('connecting to {} {} ...'.format(
                    self.engine, self.database), end='', flush=True)
                try:
                    self.connection = postgres.connect(
                        host=self.host,
                        port=self.port,
                        user=self.user,
                        password=self.password,
                        database=self.database,)
                except postgres.Error as e:
                    print('failed postgres connection error')
                    print(e)
                    self.connection = None
                    sys.exit()
                else:
                    print('done')
                    self.cursor = self.connection.cursor()
                if utils_db and isinstance(utils_db, _db):
                    try:
                        utils_db.connection.close()
                    except:
                        pass
                utils_db = self
        #
        elif self.engine == 'sqlite':
            self.p = '?'
            if utils_db and isinstance(utils_db, _db) and\
            utils_db.engine == self.engine and\
            utils_db.path == self.path and\
            utils_db.connection:
                print('database already open')
                self.connection = utils_db.connection
                self.cursor = utils_db.cursor or utils_db.connection.cursor()
            else:
                print('connecting to {} {} ...'.format(
                    self.engine, self.path), end='', flush=True)
                try:
                    self.connection = sqlite.connect(
                        self.path,
                        detect_types=sqlite.PARSE_DECLTYPES,)
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
                if utils_db and isinstance(utils_db, _db):
                    try:
                        utils_db.connection.close()
                    except:
                        pass
                utils_db = self
        #
        self.version = '0'
        if self.engine == 'mysql':
            self.version = self.get('SELECT VERSION()')[0]
        elif self.engine == 'postgres':
            self.version = self.get('SHOW server_version')[0]
        elif self.engine == 'sqlite':
            self.version = self.get('SELECT sqlite_version()')[0]
        self.version = float('.'.join(self.version.split('.')[:2]))
        if self.engine == 'mysql' and self.version < 8.0:
            self.supports_cte = False
        else:
            self.supports_cte = True

    def columns(self, table=None, show=False):
        if not table: return self.tables(True, show)
        else:
            if not isinstance(table, str): return
        self.cursor.execute('SELECT * FROM {} LIMIT 1'.format(table))
        self.data = [x[0] for x in self.cursor.description]
        if show is True:
            print(table)
            print('-' * len(table))
            for r in self.data: print (r)
        return(self.data)

    def tables(self, columns=False, show=False):
        if self.engine == 'mysql':
            self.data = self.get('SHOW TABLES', True)
        elif self.engine == 'postgres':
            self.data = self.get(dedent("""
            SELECT tablename FROM pg_catalog.pg_tables
            WHERE schemaname = 'public'
            """), True)
        elif self.engine == 'sqlite':
            self.data = self.get((strip("""
            SELECT name FROM sqlite_master WHERE type = 'table'
            """)), True)
        self.data = [x[0] for x in self.data]
        if columns is True:
            self.data = [(x, self.columns(x)) for x in self.data]
        if show is True:
            pprint(self.data)
        return self.data

    def create_table(self, table, sql, commit=True, print_log=True):
        """Takes an sql script whose first statement is create table
        The first statement is the create table statement while subsequent
        statements should be for constraints, indexes and triggers that
        further define the table.
        The table in the sql script should be referred to as {}
        """
        # Let's return a 0 if no table is created and a 1 if one is
        result = 0
        if not (table and sql):
            # Neither a table name nor an sql script were provided,
            # so we'll just quietly exit
            return 0
        #
        if table not in self.tables():
            # table does not already exist so just execute the given sql
            if print_log is not False: print(
                "creating table {} ...".format(table), end="", flush=True)
            pprint(sql)
            self.set(sql.format(table))
            if print_log is not False: print("done")
            self.connection.commit()
            return 1
        #
        # table exists, so first we'll create a temporary table
        # with the same script, then compare its properties
        # with the existing table to know if they are similar
        temp_table = "_{}_temp".format(table,)
        # if print_log is not False: print(
        #     "creating table {} ...".format(temp_table), end="", flush=True)
        self.set(sql.format(temp_table,))
        # if print_log is not False: print("done")
        old_table_def = self.table_def(table,)
        new_table_def = self.table_def(temp_table,)
        # if print_log is not False: print(
        #     "dropping table {} ...".format(temp_table), end="", flush=True)
        self.set("DROP TABLE {};".format(temp_table,))
        # if print_log is not False: print("done")
        if old_table_def == new_table_def:
            # if print_log is not False: print(
            #     "table {} not changed".format(table,))
            self.connection.commit()
            return 0
        #
        # table exists and the new table has some differences
        # Rename the old table, create the new table
        # copy data from the same column names from the old
        # table to the new table then delete the old table
        old_columns = [_[1] for _ in old_table_def]
        new_columns = [_[1] for _ in new_table_def]
        common_columns = [_ for _ in old_columns if _ in new_columns]
        old_table = "_{}_old".format(table)
        sql_copy = """INSERT INTO {0} ({2}) SELECT {2} FROM {1};
        """.format(table, old_table, ', '.join(common_columns))
        fkeys = self.foreign_keys_ref(table)
        if self.engine == "mysql":
            sql_ren = "RENAME TABLE {} TO {};".format(table, old_table)
            sql_fk0 = "SET FOREIGN_KEY_CHECKS = 0; "
            sql_fk1 = "SET FOREIGN_KEY_CHECKS = 1; "
        elif self.engine == "postgres":
            sql_ren = "ALTER TABLE {} RENAME TO {}; ".format(table, old_table)
            sql_fk0 = "; ".join(["""
            ALTER TABLE {} DROP CONSTRAINT {}
            """.format(x[0], x[1]) for x in fkeys if x]) + "; "
            sql_fk1 = "; ".join(["""
            ALTER TABLE {} ADD FOREIGN KEY ({}) REFERENCES {}({}){}{}{}
            """.format(x[0], x[2], table, x[3],
            "" if x[4] == "NONE" else x[4],
            "" if x[5] == "NO ACTION" else " ON UPDATE {}".format(x[5]),
            "" if x[6] == "NO ACTION" else " ON DELETE {}".format(x[6]),
            ) for x in fkeys if x]) + "; "
        else:
            # sqlite
            sql_ren = "ALTER TABLE {} RENAME TO {}; ".format(table, old_table)
            sql_fk0 = "PRAGMA foreign_keys=off; "
            sql_fk1 = "PRAGMA foreign_keys=on; "
        sql_drop = "DROP TABLE {};".format(old_table)
        sql1 = sql_fk0 + sql_ren + sql.format(table)
        if common_columns:
            sql1 += sql_copy
        sql1 += sql_drop + sql_fk1
        if print_log is not False: print(
            "recreating table {} and restoring data ..."
            .format(table), end="", flush=True)
        # print(sql1)
        self.set(sql1)
        if print_log is not False: print("done")
        self.connection.commit()
        return 1

    def foreign_keys_ref(self, table):
        if self.engine == 'mysql':
            return self.get(dedent("""
            SELECT
              b.table_name,
              b.constraint_name,
              b.column_name,
              b.referenced_column_name,
              c.update_rule,
              c.delete_rule
            FROM information_schema.table_constraints a
            JOIN information_schema.key_column_usage b
            ON a.table_schema = b.table_schema
            AND a.constraint_name = b.constraint_name
            JOIN information_schema.referential_constraints c
            ON a.table_schema = c.constraint_schema
            AND a.constraint_name = c.constraint_name
            WHERE a.table_schema=database()
            AND a.constraint_type='FOREIGN KEY'
            AND b.referenced_table_name='{}'
            ORDER BY b.table_name, b.constraint_name
            """.format(table)), fetchall=True)
        if self.engine == 'postgres':
            return self.get(dedent("""
            SELECT
              b.table_name,
              b.constraint_name,
              b.column_name,
              e.column_name as refrenced_column_name,
              c.match_option,
              c.update_rule,
              c.delete_rule
            FROM information_schema.table_constraints a
            JOIN information_schema.key_column_usage b
            ON a.table_schema = b.table_schema
            AND a.constraint_name = b.constraint_name
            JOIN information_schema.referential_constraints c
            ON a.table_schema = c.constraint_schema
            AND a.constraint_name = c.constraint_name
            JOIN information_schema.table_constraints d
            ON a.table_schema = d.table_schema
            AND d.table_name = '{}'
            AND c.unique_constraint_name = d.constraint_name
            JOIN information_schema.key_column_usage e
            ON a.table_schema = e.table_schema
            AND d.constraint_name = e.constraint_name
            WHERE a.constraint_type='FOREIGN KEY'
            ORDER BY b.table_name, b.constraint_name
            """.format(table)), fetchall=True)
        else:
            result = []
            for t in [x for x in self.tables() if x != table]:
                r = self.get("PRAGMA foreign_key_list({})".format(t),
                                                            fetchall=True)
                for k in r:
                    # the 3rd field [2] is the name of the table
                    # the 4th field [3] is the Foreign Key
                    # while the 5th field [4] is the field that references
                    # our primary key
                    if k[2] == table:
                        result.append((t,"") + k[3:-1])
            return result



    def table_def(self, table):
        if self.engine == 'mysql':
            return self.get(dedent("""
            SELECT
              ORDINAL_POSITION,
              COLUMN_NAME,
              COLUMN_DEFAULT,
              IS_NULLABLE,
              DATA_TYPE,
              CHARACTER_MAXIMUM_LENGTH,
              NUMERIC_PRECISION,
              DATETIME_PRECISION,
              COLUMN_TYPE,
              COLUMN_KEY,
              EXTRA
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE table_name = '{0}'
            ORDER BY ORDINAL_POSITION
            """.format(table)), fetchall=True)
        elif self.engine == 'postgres':
            return self.get("""
            SELECT
              ordinal_position,
              column_name,
              CASE WHEN column_default = CONCAT(
                  'nextval(''', '{0}_', column_name, '_seq''', '::regclass)')
                  THEN 'serial' ELSE column_default
              END AS column_default,
              is_nullable,
              data_type,
              character_maximum_length,
              numeric_precision,
              datetime_precision
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE table_name = '{0}'
            ORDER BY ordinal_position
            """.format(table), fetchall=True)
        elif self.engine == 'sqlite':
            return self.get("""
            PRAGMA table_info({0});
            """.format(table), fetchall=True)

    def drop_tables(self, commit=True):
        '''Drop all tables from tables from the database.
        It calls itself incase some tables where not dropped due
        to constraints
        '''
        tables = self.tables()
        if not tables:
            return
        for table in tables:
            print('dropping table {} ...'.format(table), end='', flush=True)
            try:
                self.cursor.execute("DROP TABLE IF EXISTS {}{};".format(
                    table, '' if self.engine == 'sqlite' else ' CASCADE'))
            except Exception as e:
                print('failed')
                # print(e)
            else:
                print('done')
        tables_left = self.tables()
        if set(tables) == set(tables_left):
            print('Error dropping tables')
            self.connection.rollback()
            sys.exit()
        if tables_left:
            self.drop_tables()
        if commit is True:
            self.connection.commit()

    def get(self, sql, fetchall=False, show=False):
        if isinstance(sql, str):
            self.sql = sql
            self.cursor.execute(self.sql)
        elif isinstance(sql, list):
            self.sql = tuple(sql)
            self.cursor.execute(*self.sql)
        elif isinstance(sql, tuple):
            self.sql = sql
            self.cursor.execute(*self.sql)
        if fetchall is False:
            self.data = self.cursor.fetchone()
            self.data = self.data or ()
        else:
            self.data = self.cursor.fetchall()
            self.data = self.data or []
        if show is True: pprint(self.data)
        return self.data

    def set(self, sql, commit=True):
        sql = dedent(sql)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if isinstance(sql, str):
                sql_list = [(sqlparse.format(statement, strip_comments=True),
                ()) for statement in sqlparse.split(
                    re.sub(r"^[\s\n;]+\|[\s\n;]+$", "", sql)
                ) if statement]
            elif isinstance(sql, (list,tuple)):
                sql_list = [(sqlparse.format(statement, strip_comments=True),
                sql[1]) for statement in sqlparse.split(
                    re.sub(r"^[\s\n;]+\|[\s\n;]+$", "", sql[0])
                ) if statement]
            else:
                return
            for s1 in sql_list:
                self.sql = s1
                pprint(self.sql)
                try:
                    self.cursor.execute(*self.sql)
                except Exception as e:
                    print('failed')
                    print(e)
                    self.connection.rollback()
                    sys.exit()
            if commit is not False:
                self.connection.commit()

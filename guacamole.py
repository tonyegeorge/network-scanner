
import net
from net import getframeinfo, currentframe, sys, os, re, logging
from net import ConfigParser, mergeConf, mysql, postgres, pprint
from net import dns_search, ldap_search, nmap_scan, host_object, hosts_dict

this_file = getframeinfo(currentframe()).filename
this_file = os.path.abspath(this_file)
this_dir = os.path.dirname(this_file)
cfg_file = re.sub(r'\.py$', '.cfg', this_file)
log_file = re.sub(r'\.py$', '.log', this_file)

config = {
    'path': cfg_file,
    'guacamole': {
        'url':       'http://localhost:8080/guacamole',
        'usergroup': 'Users',
        },
    'db': {
        'engine':   'mysql',
        'host':     'localhost',
        'user':     'guacamole',
        'password': 'guacamole',
        'database': 'guacamole_db',
        },
    'groups': {
        'kvm': 'guacamole_kvm',
        'rdp_allow': 'guacamole_rdp_allow',
        'rdp_deny': 'guacamole_rdp_deny',
        'vnc_deny': 'guacamole_vnc_deny',
        'control_deny': 'guacamole_vnc_deny_control',},
    'log': {
        'file': os.path.split(this_file)[0] + '.log',
        'level': logging.DEBUG,
        'format': "%(asctime)s: %(levelname)s: %(message)s",},
    }


parser = ConfigParser()
parser.read(config['path'])
mergeConf(config, {
    k: dict(parser.items(k))
    for k in parser.sections()
})

with open(config['ssh']['key_file']) as f0:
    privateKey = f0.read().strip()

class db(net.db):

    def __init__(self, engine=None, path=None, host=None, port=None,
        user=None, password=None, database=None, usergroup=None,
        config_file=globals()['config']['path'],
        config=globals()['config'],
        ):

        super().__init__(engine, path, host, port, user, password,
            database, config_file, config)


guac_db = db()
net_db = net.net_db()

_lu = config['linux']['user']
_au = config['windows']['user']

conn_groups = {
    'rdp'                     : {'name': '1-rdp'        },
    'vnc'                     : {'name': '2-vnc'        },
    'ssh'                     : {'name': '3-ssh'        },
    'telnet'                  : {'name': '4-telnet'     },
    'rdp/server'              : {'name': '1-server'     },
    'rdp/workstation'         : {'name': '2-workstation'},
    'rdp/linux'               : {'name': '3-linux'      },
    'ssh/linux'               : {'name': '1-linux'      },
    'ssh/server'              : {'name': '2-server'     },
    'ssh/workstation'         : {'name': '3-workstation'},
    'vnc/server'              : {'name': '1-server'     },
    'vnc/linux'               : {'name': '2-linux'      },
    'vnc/workstation'         : {'name': '3-workstation'},
    'telnet/server'           : {'name': '1-server'     },
    'telnet/workstation'      : {'name': '2-workstation'},
    'telnet/linux'            : {'name': '3-linux'      },
    'vnc/server/monitor'      : {'name': '1-monitor'    },
    'vnc/server/control'      : {'name': '2-control'    },
    'vnc/workstation/monitor' : {'name': '1-monitor'    },
    'vnc/workstation/control' : {'name': '2-control'    },
    'vnc/linux/monitor'       : {'name': '1-monitor'    },
    'vnc/linux/control'       : {'name': '2-control'    },
    'ssh/linux/root'          : {'name': '1-root'       },
    'ssh/linux/'       + _lu  : {'name': '2-' + _lu     },
    'ssh/server/'      + _au  : {'name': '1-' + _au     },
    'ssh/workstation/' + _au  : {'name': '1-' + _au     },
    'rdp/server/'      + _au  : {'name': '1-' + _au     },
    'rdp/workstation/' + _au  : {'name': '1-' + _au     },
    'rdp/linux/'       + _lu  : {'name': '1-' + _lu     },
}

def user_group_entity_id(cursor, user_group = 'Users'):
    """Get the entity_id for a specified user_group
This group is intended to give access to conn_groups
and connections created, user_groups were intoduced in
guacamole 1.0 and so will return null for prrevious
versions
"""
    select_sql = re.sub(r'\s+', ' ', """
    SELECT g.entity_id FROM guacamole_user_group g
    JOIN guacamole_entity e ON g.entity_id = e.entity_id
    WHERE e.type = %s AND e.name = %s
    """.replace('\n', ' ')).strip()

    insert_sql = re.sub(r'\s+', ' ', """
    INSERT INTO guacamole_user_group
    JOIN guacamole_entity e ON g.entity_id = e.entity_id
    WHERE e.type = %s AND e.name = %s
    """.replace('\n', ' ')).strip()

    try:
        cursor.execute(select_sql, ('USER_GROUP', user_group))
    except:
        return None
    row = cursor.fetchone()
    if row:
        return row[0]
    else:
        pass

entity_id = user_group_entity_id(guac_db.cursor)

def do_connection_group(connection_group_name, parent_id,
    db=guac_db, path = ''):
    """cg(cursor, cg_name, parent_id)
This function returns the cg_id of the
cg specified by cg_name and
parentt_id, if found it updates it with our default values
if not found, it creates it and returns the newly created
cg_id"""

    select_sql = re.sub(r'\s+', ' ', """
    SELECT `connection_group_id` FROM `guacamole_connection_group`
    WHERE `connection_group_name` = %s AND `parent_id` <=> %s
    """.replace('\n', ' ')).strip()

    delete_sql = re.sub(r'\s+', ' ', """
    DElETE FROM `guacamole_connection_group`
    WHERE `connection_group_name` = %s AND `parent_id` <=> %s
    AND `connection_group_id` <> %s
    """.replace('\n', ' ')).strip()

    update_sql = re.sub(r'\s+', ' ', """
    UPDATE `guacamole_connection_group` SET
    `type` = %s, `max_connections` = %s,
    `max_connections_per_user` = %s, `enable_session_affinity` = %s
    WHERE `connection_group_name` = %s AND `parent_id` <=> %s
    """.replace('\n', ' ')).strip()

    insert_sql = re.sub(r'\s+', ' ', """
    INSERT INTO `guacamole_connection_group`
    (`type`,`max_connections`,`max_connections_per_user`,
    `enable_session_affinity`, `connection_group_name`, `parent_id`)
    VALUES (%s, %s, %s, %s, %s, %s)
    """.replace('\n', ' ')).strip()

    value_list = ('ORGANIZATIONAL', 100, 100, 1,
        connection_group_name, parent_id)

    change = 0

    row = db.get((select_sql, (connection_group_name, parent_id)))

    # cursor.execute(select_sql, (connection_group_name, parent_id))
    # row = cursor.fetchone()

    if row:
        connection_group_id = row[0]
        if cursor.rowcount > 1:
            cursor.execute(delete_sql,
                (connection_group_name, parent_id, connection_group_id))
            if cursor.rowcount > 0:
                change = 2

        db.set((update_sql, value_list))
        if db.cursor.rowcount > 0:
            change = 2

    else:
        db((insert_sql, value_list))
        connection_group_id = db.cursor.lastrowid
        if db.cursor.rowcount > 0:
            change = 1

    if entity_id:
        upsert_sql = re.sub(r'\s+', ' ', """
        INSERT IGNORE `guacamole_connection_group_permission`
        (`entity_id`, `connection_group_id`, `permission`)
        VALUES (%s, %s, %s)
        """.replace('\n', ' ')).strip()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            db.cursor.execute(upsert_sql,
                (entity_id, connection_group_id, 'READ'))
        if db.cursor.rowcount > 0 and change == 0:
            change = 2
    ##############################################
    # log
    if   change == 1: change = 'created'
    elif change == 2: change = 'updated'
    else:             change = 'unchanged'
    # print 'connection_group_id', str(connection_group_id), change, path
    ##############################################

    return connection_group_id

def do_cgs():

    for i in range(1,5):
        for key in (k for k, v in conn_groups.items()
            if len(k.split('/')) == i):

            if i == 1:
                conn_groups[key]['parent_id'] = do_connection_group(
                    config['ldap']['fqdn'],
                    None,
                    db=guac_db,
                )
            else:
                conn_groups[key]['parent_id'] = conn_groups[
                    os.path.dirname(key)]['id']

            conn_groups[key]['id'] = do_connection_group(
                conn_groups[key]['name'],
                conn_groups[key]['parent_id'],
                db=guac_db,
            )


def do_connection(connection_dicti, db=guac_db):
    """connection(cursor, connection_name, parent_id)
This function returns the connection_id of the
connection specified by objCon a python tuple and
if found it updates it with our default values
if not found, it creates it and returns the newly created
connection_id"""

    # First we initialize the field lists to get from the tuple
    update_field_list, update_value_list = [], []
    insert_field_list, insert_value_list, insert_value_para = [], [], []
    delete_field_list = []

    conn = {k:v for k,v in connection_dict.items()
        if not isinstance(v, dict) and v is not None}

    para = {k:v for k,v in connection_dict['parameter'].items()
        if not isinstance(v, dict) and v is not None}

    for key,val in conn.items():

        if not re.search('^(connection_(name|id)|parent_id)$', key):
            update_field_list.append('`{}` = %s'.format(key))
            update_value_list.append(str(val))

        if not re.search('^connection_id$', key):
            insert_field_list.append('`{}`'.format(key))
            insert_value_list.append(str(val))

    for key in para:
        delete_field_list.append('{}'.format(key))

    ##############################################
    upsert_sql = re.sub(r'\s+', ' ', """
    INSERT INTO `guacamole_connection`
    ({}) VALUES ({}) ON DUPLICATE KEY UPDATE {}
    """.format(
        ', '.join(insert_field_list),
        ', '.join(('%s',) * len(insert_field_list)),
        ', '.join(['connection_id = LAST_INSERT_ID(connection_id)'] + update_field_list)
    ).replace('\n', ' ')).strip()
    db.set((upsert_sql, (insert_value_list + update_value_list)))
    connection_dict['connection_id'] = db.cursor.lastrowid
    conn_change = db.cursor.rowcount
    para_change = 0
    ##############################################
    for ky, vl in para.items():
        if vl:
            upsert_sql = re.sub(r'\s+', ' ', """
            INSERT INTO `guacamole_connection_parameter`
            (`connection_id`, `parameter_name`, `parameter_value`)
            VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE `parameter_value` = %s
            """.replace('\n', ' ')).strip()

            db.set((upsert_sql, (connection_dict['connection_id'], ky, vl, vl)))
            if db.cursor.rowcount > 0: para_change = db.cursor.rowcount
    ##############################################
    delete_sql = re.sub(r'\s+', ' ', """
    DELETE FROM `guacamole_connection_parameter`
    WHERE `connection_id` = %s AND `parameter_name` NOT IN ({})
    """.format(', '.join(['%s'] * len(delete_field_list))
    ).replace('\n', ' ')).strip()

    db.set((delete_sql,
        ([connection_dict['connection_id']] + delete_field_list)))
    if db.cursor.rowcount > 0: para_change = db.cursor.rowcount
    ##############################################
    if entity_id:

        if connection_dict['extra']['allow'] is True:
            sql = re.sub(r'\s+', ' ', """
            INSERT IGNORE `guacamole_connection_permission`
            (`entity_id`, `connection_id`, `permission`)
            VALUES (%s, %s, %s)
            """.replace('\n', ' ')).strip()
        else:
            sql = re.sub(r'\s+', ' ', """
            DELETE FROM `guacamole_connection_permission`
            WHERE `entity_id` = %s
            AND `connection_id` = %s AND `permission` = %s
            """.replace('\n', ' ')).strip()

        db.set((sql, (entity_id, connection_dict['connection_id'], 'READ')))
        if db.cursor.rowcount > 0: para_change = db.cursor.rowcount
    ##############################################
    # log
    if   conn_change == 1:                    change = 'created'
    elif conn_change == 2 or para_change > 0: change = 'updated'
    else:                                     change = 'unchanged'
    print('connection_id',
          str(connection_dict['connection_id']),
          change,connection_dict['extra']['path'])
    ##############################################

    return connection_dict['connection_id']

def do_rdp(path, host, port):
    result = {
        # 'connection_name': host.name.lower(),
        'connection_name': os.path.basename(path),
        'failover_only': 0,
        'max_connections': 100,
        'max_connections_per_user': 100,
        'parent_id': conn_groups[os.path.dirname(path.lower())]['id'],
        'protocol': 'rdp',
        'parameter': {
            'disable-audio': 'true',
            'disable-auth': 'true',
            'enable-desktop-composition': 'true',
            'enable-font-smoothing': 'true',
            'enable-full-window-drag': 'true',
            'enable-theming': 'true',
            'enable-wallpaper': 'true',
            'hostname': host.dNSHostName if host.dNSHostName else host.ipv4,
            'ignore-cert': 'true',
            'port': port,
        },
        'extra': {
            'path': path.lower(),
            'groups': host.groups,
            'allow': config['groups']['rdp_deny'] not in host.groups and(
                config['groups']['rdp_allow'] in host.groups or (
                config['linux']['user'] not in path and (
                config['ldap']['user'] not in path))),
        },
    }
    if host.osFamily and host.osFamily == 'windows' and host.osVersion:
        try:
            _v = int(host.osVersion)
        except:
            result['parameter']['security'] = 'rdp'
        else:
            result['parameter']['security'] = 'tls' if _v > 5 else 'rdp'
    else:
        result['parameter']['security'] = 'rdp'

    if config['ldap']['user'] in path:
        result['parameter']['username'] = config['ldap']['user']
        result['parameter']['password'] = config['ldap']['password']
        result['parameter']['domain'] = config['ldap']['fqdn']
    elif config['linux']['user'] in path:
        result['parameter']['username'] = config['linux']['user']
        result['parameter']['password'] = config['linux']['password']
        result['parameter']['domain'] = None
    else:
        result['parameter']['username'] = None
        result['parameter']['password'] = None
        result['parameter']['domain'] = None

    result['connection_id'] = do_connection(guac_db.cursor, result)

    return result

def do_vnc(path, host, port):
    result = {
        'connection_name': os.path.basename(path),
        'failover_only': 0,
        'max_connections': 100,
        'max_connections_per_user': 100,
        'parent_id': conn_groups[os.path.dirname(path.lower())]['id'],
        'protocol': 'vnc',
        'parameter': {
            'hostname': host.dNSHostName if host.dNSHostName else host.ipv4,
            'port': port,
            'password': config['vnc']['password'],
            'read-only': 'false' if 'control' in path else 'true',
        },
        'extra': {
            'path': path.lower(),
            'groups': host.groups,
            'allow': not (config['groups']['vnc_deny'] in host.groups or (
                'control' in path and (
                config['groups']['control_deny'] in host.groups))),
        },
    }


    result['connection_id'] = do_connection(guac_db.cursor, result)

    return result

def do_ssh(path, host, port):
    result = {
        'connection_name': os.path.basename(path),
        'failover_only': 0,
        'max_connections': 100,
        'max_connections_per_user': 100,
        'parent_id': conn_groups[os.path.dirname(path.lower())]['id'],
        'protocol': 'ssh',
        'parameter': {
            'hostname': host.dNSHostName if host.dNSHostName else host.ipv4,
            'port': port,
        },
        'extra': {
            'path': path.lower(),
            'groups': host.groups,
        },
    }
    if re.search(r'\broot\b|\b{}\b|\b{}\b'.format(
            config['linux']['user'],
            config['ldap']['user']
        ), path):

        if re.search(r'\blinux\b', path):
            if re.search(r'\broot\b', path):
                result['parameter']['username'] = 'root'
            else:
                result['parameter']['username'] = config['linux']['user']
                result['parameter']['password'] = config['linux']['password']
        else:
            result['parameter']['username'] = '{}\\{}'.format(config['ldap']['domain'], config['ldap']['user'])
            result['parameter']['password'] = config['ldap']['password']

        result['parameter']['private-key'] = privateKey
        result['extra']['allow'] = False
    else:
        result['extra']['allow'] = True


    result['connection_id'] = do_connection(guac_db.cursor, result)

    return result

def do_telnet(path, host, port):
    result = {
        'connection_name': os.path.basename(path),
        'failover_only': 0,
        'max_connections': 100,
        'max_connections_per_user': 100,
        'parent_id': conn_groups[os.path.dirname(path.lower())]['id'],
        'protocol': 'telnet',
        'parameter': {
            'hostname': host.dNSHostName if host.dNSHostName else host.ipv4,
            'port': port,
        },
        'extra': {
            'path': path.lower(),
            'groups': host.groups,
            'allow': True,
        },
    }



def do_hosts(hosts):

    for k,v in hosts.items():
        if not (v.tcp and (v.name or v.ipv4)):
            continue

        ssh_list = [int(l) for l,w in v.tcp.items()
            if w['name'] == 'ssh' or int(l) == 22]
        rdp_list = [int(l) for l,w in v.tcp.items()
            if w['name'] == 'ms-wbt-server' or int(l) == 3389]
        vnc_list = [int(l) for l,w in v.tcp.items()
            if w['name'] == 'vnc' or int(l) == 5899 or int(l) == 5900]
        tel_list = [int(l) for l,w in v.tcp.items()
            if w['name'] == 'telnet' or int(l) == 23]

        if v.osType:
            if v.osType.lower() == 'linux':
                _user = config['linux']['user']
            else:
                _user = config['ldap']['user']

        # rdp
        if v.osType and v.osType in ('server', 'workstation', 'linux'):
            cg1 = 'rdp/{}'.format(v.osType)
            # cg2 = 'rdp/{}'.format(_user)
            cg3 = 'rdp/{}/{}'.format(v.osType, _user)
            cg4 = 'rdp/{}/{}'.format(_user, v.osType)
        else:
            cg1 = 'rdp'

        rp1 = '{}/{}'.format(cg1, v.name)
        if v.osType and v.osType in ('server', 'workstation', 'linux'):
            # rp2 = '{}/{}'.format(cg2, v.name)
            rp3 = '{}/{}'.format(cg3, v.name)
            rp4 = '{}/{}'.format(cg4, v.name)

        if len(rdp_list) > 1:

            conn_groups[rp1] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(rp1)]['id']}
            if v.osType and v.osType in ('server', 'workstation', 'linux'):
                # conn_groups[rp2] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(rp2)]['id']}
                conn_groups[rp3] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(rp3)]['id']}
                conn_groups[rp4] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(rp4)]['id']}

                conn_groups[rp1]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[rp1]['parent_id'])
                # conn_groups[rp2]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[rp2]['parent_id'])
                conn_groups[rp3]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[rp3]['parent_id'])
                conn_groups[rp4]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[rp4]['parent_id'])

                cgi1 = do_cg(guac_db.cursor, v.name, conn_groups[cg1]['id'], rp1)
                # cgi2 = do_cg(guac_db.cursor, v.name, conn_groups[cg2]['id'], rp2)
                cgi3 = do_cg(guac_db.cursor, v.name, conn_groups[cg3]['id'], rp3)
                cgi4 = do_cg(guac_db.cursor, v.name, conn_groups[cg4]['id'], rp4)

            for _port in rdp_list:

                rp1 = '{0}/{1}/{1}-{2}'.format(cg1, v.name, _port)
                if v.osType and v.osType in ('server', 'workstation', 'linux'):
                    # rp2 = '{0}/{1}/{1}-{2}'.format(cg2, v.name, _port)
                    rp3 = '{0}/{1}/{1}-{2}'.format(cg3, v.name, _port)
                    rp4 = '{0}/{1}/{1}-{2}'.format(cg4, v.name, _port)

                rd1 = do_rdp(rp1, v, rdp_list[0])
                if v.osType and v.osType in ('server', 'workstation', 'linux'):
                    # rd2 = do_rdp(rp2, v, rdp_list[0])
                    rd3 = do_rdp(rp3, v, rdp_list[0])
                    rd4 = do_rdp(rp4, v, rdp_list[0])

        elif len(rdp_list) > 0:

            rd1 = do_rdp(rp1, v, rdp_list[0])
            if v.osType and v.osType in ('server', 'workstation', 'linux'):
                # rd2 = do_rdp(rp2, v, rdp_list[0])
                rd3 = do_rdp(rp3, v, rdp_list[0])
                rd4 = do_rdp(rp4, v, rdp_list[0])

        # vnc

        if v.osType and v.osType in ('server', 'workstation', 'linux'):
            cg1 = 'vnc/{}/control'.format(v.osType)
            cg2 = 'vnc/{}/monitor'.format(v.osType)
            cg3 = 'vnc/control/{}'.format(v.osType)
            cg4 = 'vnc/monitor/{}'.format(v.osType)
        else:
            cg1 = 'vnc'

        vp1 = '{}/{}'.format(cg1, v.name)
        if v.osType and v.osType in ('server', 'workstation', 'linux'):
            vp2 = '{}/{}'.format(cg2, v.name)
            vp3 = '{}/{}'.format(cg3, v.name)
            vp4 = '{}/{}'.format(cg4, v.name)

        if len(vnc_list) > 1:

            conn_groups[vp1] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(vp1)]['id']}
            if v.osType and v.osType in ('server', 'workstation', 'linux'):
                conn_groups[vp2] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(vp2)]['id']}
                conn_groups[vp3] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(vp3)]['id']}
                conn_groups[vp4] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(vp4)]['id']}

            conn_groups[vp1]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[vp1]['parent_id'])
            if v.osType and v.osType in ('server', 'workstation', 'linux'):
                conn_groups[vp2]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[vp2]['parent_id'])
                conn_groups[vp3]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[vp3]['parent_id'])
                conn_groups[vp4]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[vp4]['parent_id'])

            cgi1 = do_cg(guac_db.cursor, v.name, conn_groups[cg1]['id'], vp1)
            if v.osType and v.osType in ('server', 'workstation', 'linux'):
                cgi2 = do_cg(guac_db.cursor, v.name, conn_groups[cg2]['id'], vp2)
                cgi3 = do_cg(guac_db.cursor, v.name, conn_groups[cg3]['id'], vp3)
                cgi4 = do_cg(guac_db.cursor, v.name, conn_groups[cg4]['id'], vp4)

            for _port in vnc_list:

                vp1 = '{0}/{1}/{1}-{2}'.format(cg1, v.name, _port)
                if v.osType and v.osType in ('server', 'workstation', 'linux'):
                    vp2 = '{0}/{1}/{1}-{2}'.format(cg2, v.name, _port)
                    vp3 = '{0}/{1}/{1}-{2}'.format(cg3, v.name, _port)
                    vp4 = '{0}/{1}/{1}-{2}'.format(cg4, v.name, _port)

                vd1 = do_vnc(vp1, v, vnc_list[0])
                if v.osType and v.osType in ('server', 'workstation', 'linux'):
                    vd2 = do_vnc(vp2, v, vnc_list[0])
                    vd3 = do_vnc(vp3, v, vnc_list[0])
                    vd4 = do_vnc(vp4, v, vnc_list[0])

        elif len(vnc_list) > 0:

            vd1 = do_vnc(vp1, v, vnc_list[0])
            if v.osType and v.osType in ('server', 'workstation', 'linux'):
                vd2 = do_vnc(vp2, v, vnc_list[0])
                vd3 = do_vnc(vp3, v, vnc_list[0])
                vd4 = do_vnc(vp4, v, vnc_list[0])

        # ssh

        if v.osType and v.osType in ('server', 'workstation', 'linux'):
            cg1 = 'ssh/{}'.format(v.osType)
            cg2 = 'ssh/{}/{}'.format(v.osType, _user)
            # cg3 = 'ssh/{}'.format(_user)
        else:
            cg1 = 'ssh'

        sp1 = '{}/{}'.format(cg1, v.name)
        if v.osType and v.osType in ('server', 'workstation', 'linux'):
            sp2 = '{}/{}'.format(cg2, v.name)
            # sp3 = '{}/{}'.format(cg3, v.name)

        if v.osType and v.osType in ('server', 'workstation', 'linux'):
            if v.osType != 'linux':
                cg4 = 'ssh/{}/{}'.format(_user, v.osType)
            else:
                cg5 = 'ssh/root'
                cg4 = 'ssh/{}'.format(_user)
                cg6 = 'ssh/{}/root'.format(v.osType)
                cg7 = 'ssh/root'

                sp5 = '{}/{}'.format(cg5, v.name)
                sp6 = '{}/{}'.format(cg6, v.name)
                sp7 = '{}/{}'.format(cg7, v.name)

            sp4 = '{}/{}'.format(cg4, v.name)

        if len(ssh_list) > 1:

            conn_groups[sp1] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(sp1)]['id']}
            if v.osType and v.osType in ('server', 'workstation', 'linux'):
                conn_groups[sp2] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(sp2)]['id']}
                # conn_groups[sp3] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(sp3)]['id']}
                conn_groups[sp4] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(sp4)]['id']}

            conn_groups[sp1]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[sp1]['parent_id'])
            if v.osType and v.osType in ('server', 'workstation', 'linux'):
                conn_groups[sp2]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[sp2]['parent_id'])
                # conn_groups[sp3]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[sp3]['parent_id'])
                conn_groups[sp4]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[sp4]['parent_id'])

            cgi1 = do_cg(guac_db.cursor, v.name, conn_groups[cg1]['id'], sp1)
            if v.osType and v.osType in ('server', 'workstation', 'linux'):
                cgi2 = do_cg(guac_db.cursor, v.name, conn_groups[cg2]['id'], sp2)
                # cgi3 = do_cg(guac_db.cursor, v.name, conn_groups[cg3]['id'], sp3)
                cgi4 = do_cg(guac_db.cursor, v.name, conn_groups[cg4]['id'], sp4)

                if v.osType == 'linux':

                    conn_groups[sp5] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(sp5)]['id']}
                    conn_groups[sp6] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(sp6)]['id']}
                    conn_groups[sp7] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(sp7)]['id']}

                    conn_groups[sp5]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[sp5]['parent_id'])
                    conn_groups[sp6]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[sp6]['parent_id'])
                    conn_groups[sp7]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[sp7]['parent_id'])

                    cgi5 = do_cg(guac_db.cursor, v.name, conn_groups[cg5]['id'], sp5)
                    cgi6 = do_cg(guac_db.cursor, v.name, conn_groups[cg6]['id'], sp6)
                    cgi7 = do_cg(guac_db.cursor, v.name, conn_groups[cg7]['id'], sp7)

            for _port in ssh_list:

                sp1 = '{0}/{1}/{1}-{2}'.format(cg1, v.name, _port)
                if v.osType and v.osType in ('server', 'workstation', 'linux'):
                    sp2 = '{0}/{1}/{1}-{2}'.format(cg2, v.name, _port)
                    # sp3 = '{0}/{1}/{1}-{2}'.format(cg3, v.name, _port)
                    sp4 = '{0}/{1}/{1}-{2}'.format(cg4, v.name, _port)

                sd1 = do_ssh(sp1, v, ssh_list[0])
                if v.osType and v.osType in ('server', 'workstation', 'linux'):
                    sd2 = do_ssh(sp2, v, ssh_list[0])
                    # sd3 = do_ssh(sp3, v, ssh_list[0])
                    sd4 = do_ssh(sp4, v, ssh_list[0])

                    if v.osType == 'linux':

                        sp5 = '{0}/{1}/{1}-{2}'.format(cg5, v.name, _port)
                        sp6 = '{0}/{1}/{1}-{2}'.format(cg6, v.name, _port)
                        sp7 = '{0}/{1}/{1}-{2}'.format(cg7, v.name, _port)

                        sd5 = do_ssh(sp5, v, ssh_list[0])
                        sd6 = do_ssh(sp6, v, ssh_list[0])
                        sd7 = do_ssh(sp7, v, ssh_list[0])

        elif len(ssh_list) > 0:

            sd1 = do_ssh(sp1, v, ssh_list[0])
            if v.osType and v.osType in ('server', 'workstation', 'linux'):
                sd2 = do_ssh(sp2, v, ssh_list[0])
                # sd3 = do_ssh(sp3, v, ssh_list[0])
                sd4 = do_ssh(sp4, v, ssh_list[0])

                if v.osType == 'linux':

                    sd5 = do_ssh(sp5, v, ssh_list[0])
                    sd6 = do_ssh(sp6, v, ssh_list[0])
                    sd7 = do_ssh(sp7, v, ssh_list[0])

        # telnet

        if v.osType and v.osType.lower() in ('windows', 'linux'):
            cg1 = 'telnet/{}'.format(v.osType)
        else:
            cg1 = 'telnet'

        tp1 = '{}/{}'.format(cg1, v.name)

        if len(tel_list) > 1:

            conn_groups[tp1] = {'name': v.name, 'parent_id': conn_groups[os.path.dirname(tp1)]['id']}
            conn_groups[tp1]['id'] = do_cg(guac_db.cursor, v.name, conn_groups[tp1]['parent_id'])
            cgi1 = do_cg(guac_db.cursor, v.name, conn_groups[cg1]['id'], tp1)

            for _port in tel_list:

                tp1 = '{0}/{1}/{1}-{2}'.format(cg1, v.name, _port)
                td1 = do_telnet(tp1, v, tel_list[0])

        elif len(tel_list) > 0:

            td1 = do_telnet(tp1, v, tel_list[0])

hosts = hosts_dict(config=config)
# do_hosts()
# hosts = net.hosts(config=config, db=db)

# do_cgs()
# guac_db.conn.commit()


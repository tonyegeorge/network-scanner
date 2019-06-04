import unittest
import net

class TestNet(unittest.TestCase):

    def test_mysql_init(self):
        my_db = net.net_db(engine='mysql', init=True)
        self.assertEqual(set(my_db.tables()), set(['dns', 'ldap', 'nmap']))

    def test_mysql_full(self):
        try:
            my_db = net.net_db(engine='mysql', init=False)
            host_dict = net.dns_search(db=my_db)
            host_dict = net.ldap_search(db=my_db, host_dict=host_dict)
            host_dict = net.nmap_scan(db=my_db, host_dict=host_dict, hosts='127.0.0.1')
        except:
            self.fail("test_mysql_full() raised an exception unexpectedly!")

    def test_postgres_init(self):
        my_db = net.net_db(engine='postgres', init=True)
        self.assertEqual(set(my_db.tables()), set(['dns', 'ldap', 'nmap']))

    def test_postgres_full(self):
        try:
            my_db = net.net_db(engine='postgres', init=False)
            host_dict = net.dns_search(db=my_db)
            host_dict = net.ldap_search(db=my_db, host_dict=host_dict)
            host_dict = net.nmap_scan(db=my_db, host_dict=host_dict, hosts='127.0.0.1')
        except:
            self.fail("test_postgres_full() raised an exception unexpectedly!")

    def test_sqlite_init(self):
        my_db = net.net_db(engine='sqlite', init=True)
        self.assertEqual(set(my_db.tables()), set(['dns', 'ldap', 'nmap']))

    def test_sqlite_full(self):
        try:
            my_db = net.net_db(engine='sqlite', init=False)
            host_dict = net.dns_search(db=my_db)
            host_dict = net.ldap_search(db=my_db, host_dict=host_dict)
            host_dict = net.nmap_scan(db=my_db, host_dict=host_dict, hosts='127.0.0.1')
        except:
            self.fail("test_sqlite_full() raised an exception unexpectedly!")

if __name__ == '__main__':
    unittest.main()

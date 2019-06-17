import unittest
import net

tables = 'host', 'dns', 'nmap', 'ldap'
engines = 'mysql', 'postgres', 'sqlite'

class TestNet(unittest.TestCase):

    def test_db(self):
        global tables
        global engines

        def test_db_engine(engine):
            def test_db_engine_assert():
                self.assertEqual(set(db.tables()), set(tables))
                self.assertEqual(db.engine, engine)

            db = net._db(engine=engine, init=True)
            test_db_engine_assert
            db = net._db(engine=engine)
            test_db_engine_assert

        for e in engines:
            test_db_engine(e)

    def test_dns_search(self):
        global tables
        net.dns_search()
        self.assertTrue(isinstance(net.net_db, net._db))
        engine1 = net.net_db.engine
        for e in [x for x in engines if x != engine1]:
            db = None
            db = net._db(engine=e, set_db=False, set_hosts=False)
            net.dns_search(db=db)
            self.assertEqual(net.net_db.engine, engine1)



if __name__ == '__main__':
    unittest.main()

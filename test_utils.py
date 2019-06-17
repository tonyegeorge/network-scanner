import unittest
import utils
from utils import *
class TestUtils(unittest.TestCase):
    #
    def test_strip(self):
        test = [['''
        SELECT      james    FROM ( Jon
        )
        ''',
        'SELECT james FROM (Jon)'],
        ]
        for x in test:
            # print('strip({})\nshould give\n{}'.format(x[0], x[1]))
            self.assertEqual(strip(x[0]), x[1])
    #
    def test_db(self):
        global utils_db
        path = 'net.db'
        host = 'localhost'
        user = 'net_db'
        password = 'net_db'
        database = 'net_db'
        for engine in 'mysql', 'postgres', 'sqlite':
            try:
                with self.assertRaises(SystemExit):
                    db1 = utils._db(path=path, host=host, user=user,
                        password=password, database=database, engine=engine)
            except:
                self.assertEqual(isinstance(utils.utils_db, utils._db), True)
                self.assertEqual(utils.utils_db, db1)
            try:
                with self.assertRaises(SystemExit):
                    db1 = utils._db(path=path, host=host, user=user,
                        password=password, database=database, engine=engine)
                    db2 = utils._db(path=path, host=host, user=user,
                        password=password, database=database, engine=engine)
            except:
                self.assertEqual(isinstance(utils.utils_db, utils._db), True)
#
if __name__ == '__main__':
    unittest.main()

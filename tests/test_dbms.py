from cvemanager import cve_dbms as db

class TestDatabase(object):

    class DummyArgs(object):
        def __init__(self, mypassword, database, myuser='postgres', myhost='localhost', cve=None, score=None, date=-1, out=False):
            self.myuser = myuser
            self.mypassword = mypassword
            self.myhost = myhost
            self.database = database
            self.cve = cve
            self.score = score
            self.date = date
            self.out = out

    class DummyArgsCwe(object):
        def __init__(self, mypassword, database, myuser='postgres', myhost='localhost', cve=None, out=False):
            self.myuser = myuser
            self.mypassword = mypassword
            self.myhost = myhost
            self.database = database
            self.cve = cve
            self.out = out

    def test_database(self):
        pw = input()
        args = self.DummyArgs(pw, 'cve')

        with open('./tests/correct_results.txt', 'r', encoding='utf-8') as f:
            args.cve = '2019-2434'
            answer = db.execute_query(**args.__dict__)
            line = f.readline().strip()

            assert str(answer) == line

            args.cve = '2020-5'
            args.score = 9.9
            args.date = 2019

            answer = db.execute_query(**args.__dict__)
            line = f.readline().strip()

            assert str(answer) == line

            args = self.DummyArgsCwe(pw, 'cve')

            args.cve = 'CVE-2019-2434'

            answer = db.query_for_cwe(**args.__dict__)
            line = f.readline().strip()

            assert str(answer) == line

            args.cve = 'CVE-2020-6963'

            answer = db.query_for_cwe(**args.__dict__)
            line = f.readline().strip()

            assert str(answer) == line


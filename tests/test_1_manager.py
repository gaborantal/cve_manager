import os

from cvemanager import cve_manager as manager

class TestManager(object):

    class DummyArgs(object):
        def __init__(self, input='nvd/', results='results/', year=False, csv=False, download=False, process=False,
                     idb=False, user='postgres', owner=None, dd=False, cd=False, ct=False, tr=False, cve=None,
                     score=None, date=-1, cwe=None):
            self.input = input
            self.results = results
            self.year = year
            self.csv = csv
            self.download = download
            self.process = process
            self.idb = idb
            self.user = user
            self.owner = owner
            self.dd = dd
            self.cd = cd
            self.ct = ct
            self.tr = tr
            self.cve = cve
            self.score = score
            self.date = date
            self.cwe = cwe

    def test_cve_managing(self):
        args = self.DummyArgs()

        args.download = True

        manager.manage_cves(args)

        args.download = False
        args.csv = True
        args.process = True

        manager.manage_cves(args)

    def test_cve_download(self):
        assert os.path.exists('./nvd') == True
        assert (len(os.listdir('./nvd')) > 0) == True

    def test_cve_processing(self):
        assert os.path.exists('./results') == True
        assert os.path.exists('./results/cve_cpes.csv') == True
        assert os.path.exists('./results/cve_cvss_scores.csv') == True
        assert os.path.exists('./results/cve_related_problems.csv') == True


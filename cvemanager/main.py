import argparse

from . import cve_manager

def main():
    parser = argparse.ArgumentParser(description='CVEs Manager.')  # version='0.1'
    parser.add_argument('-p', '--parse', action="store_true", dest="process", default=False, help="Process downloaded CVEs.")
    parser.add_argument('-d', '--download', action="store_true", dest="download", default=False, help="Download CVEs.")
    parser.add_argument('-y', '--year', action="store", dest="year", default=False, help="The year for which CVEs shall be downloaded (e.g. 2019)")
    parser.add_argument('-csv', '--cvs_files', action="store_true", dest="csv", default=False, help="Create CSVs files.")
    parser.add_argument('-idb', '--import_to_db', action="store_true", dest="idb", default=False, help="Import CVEs into a database.")
    parser.add_argument('-i', '--input', action="store", default='nvd/', dest="input", help="The directory where NVD json files will been downloaded, and the one from where they will be parsed (default: nvd/")
    parser.add_argument('-o', '--output', action="store", default='results/', dest="results", help="The directory where the csv files will be stored (default: results/")
    parser.add_argument('-u', '--user', action="store", dest="user", default="postgres", help="The user to connect to the database.")
    parser.add_argument('-ow', '--owner', action="store", dest="owner", default=None, help="The owner of the database (if different from the connected user).")
    parser.add_argument('-ps', '--password', action="store", dest="password", default="", help="The password to connect to the database.")
    parser.add_argument('-host', '--host', action="store", dest="host", default="localhost", help="The host or IP of the database server.")
    parser.add_argument('-db', '--database', action="store", dest="database", default="postgres", help="The name of the database.")
    parser.add_argument('-cd', '--create_database', action="store_true", dest="cd", default=False, help="Create the database")
    parser.add_argument('-dd', '--drop_database', action="store_true", dest="dd", default=False, help="Drop the database")
    parser.add_argument('-ct', '--create_tables', action="store_true", dest="ct", default=False, help="Create the tables of the database")
    parser.add_argument('-tr', '--truncate_cves_tables', action="store_true", dest="tr", default=False, help="Truncate the CVEs-related tables")
    parser.add_argument('-cve', '--cvs_number', action="store", dest="cve", default=None, help="Print info for a CVE (CVSS score and other)")
    parser.add_argument('-sc', '--score', action="store", dest="score", default=None, help="Use base score of a CVE as a selection criterion")
    parser.add_argument('-dt', '--date', action="store", dest="date", default=-1, help="Use publication date of a CVE as a selection criterion")
    parser.add_argument('-cwe', '--cwe', action="store", dest="cwe", default=None, help="Query for cwe group of specified cve")
    values = parser.parse_args()

    cve_manager.manage_cves(values)

if __name__ == '__main__':
    main()
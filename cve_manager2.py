#!/usr/bin/python
#check out the ~/.pgpass file to store password securely and not in the source code (http://www.postgresql.org/docs/9.2/static/libpq-pgpass.html). libpq, the postgresql client librairy, check for this file to get proper login information.

import psycopg2
from psycopg2 import Error
from psycopg2 import connect
import sys
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import os
from os import listdir
from os.path import isfile, join, exists
from os import makedirs
import argparse
import zipfile
import json
import requests
import re
import io
import cve_dbms as db

def download_cves(directory, year):
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
        except OSError:
            print(('Error: Creating directory. ' + directory))
            exit(0)
        else:  
            print(("Successfully created the directory %s" % directory))
    else:
        print(("Directory %s already exists" % directory))
    r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    if year:
        print(("downloading ", year, " only"))
        filename = "nvdcve-1.1-"+year+".json.zip"
        print(filename)
        r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
        with open(directory + "/" + filename, 'wb') as f:
            for chunk in r_file:
                f.write(chunk)
    else:
        for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip", r.text):
            print(filename)
            r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
            with open(directory + "/" + filename, 'wb') as f:
                for chunk in r_file:
                    f.write(chunk)

def process_cves(directory, results, csv, import_db, myuser, mypassword, myhost, database):
    if csv:
        if not os.path.exists(results):
            try:
                os.makedirs(results)
            except OSError:
                print(('Error: Creating directory. ' + results))
                exit(0)
            else:  
                print(("Successfully created the directory %s" % results))
        else:
            print(("Directory %s already exists" % results))
        file_cve_related_problems = open(results+"cve_related_problems.csv", "w", encoding="utf-8")
        file_cvss_score = open(results+"cve_cvss_scores.csv", "w", encoding="utf-8")
        file_cpes = open(results+"cve_cpes.csv", "w", encoding="utf-8")
        file_cve_related_problems.write("cve_data\tcwe_group\tpublished_date\tseverity\timpact_score\n")
        file_cpes.write("CVE\tcpe22Uri\tcpe23Uri\tVulnerable\n")
        file_cvss_score.write("CVE\tAttack Complexity\tAttack Vector\tAvailability Impact\tConfidentiality Impact\tIntegrity Impact\tPrivileges Required\tScope\tUserInteraction\tVector String\tExploitability Score\tImpact Score\tbase Score\tbase Severity\tAccess Complexity\tAccess Vector\tAuthentication\tAvailability Impact\tConfidentiality Impact\tIntegrityImpact\tObtain All Privilege\tobtain Other Privilege\tobtain User Privilege\tuser Interaction Required\tvector String\tExploitability Score\timpact Score\tbaseScore\tseverity\tDescription\tPublished Date\tLast Modified Date\n")
        ########################################################################################
        all_cves = []
        directory = directory + "/"
        files = [f for f in listdir(directory) if isfile(join(directory, f))]
        files.sort(reverse=True)
        for file in files:
            print("\nProcessing", file)
            archive = zipfile.ZipFile(join(directory, file), 'r')
            jsonfile = archive.open(archive.namelist()[0])
            cve_dict = json.loads(jsonfile.read())
            print(("CVE_data_timestamp: " + str(cve_dict['CVE_data_timestamp'])))
            print(("CVE_data_version: " + str(cve_dict['CVE_data_version'])))
            print(("CVE_data_format: " + str(cve_dict['CVE_data_format'])))
            print(("CVE_data_number of CVEs: " + str(cve_dict['CVE_data_numberOfCVEs'])))
            print(("CVE_data_type: " + str(cve_dict['CVE_data_type'])))
            all_cves = all_cves + cve_dict['CVE_Items']
            #print(json.dumps(cve_dict['CVE_Items'][0], sort_keys=True, indent=4, separators=(',', ': ')))
            jsonfile.close()
        cvssv_score = []
        for cves in all_cves:
            cve = cves['cve']['CVE_data_meta']['ID']
            description = ""
            for descriptions in cves['cve']['description']['description_data']:
                description = description + descriptions['value']
            if description.find("** REJECT **"):
                description = description.replace('\r\n', ' ')
                description = description.replace('\n', ' ')
                description = description.replace('\t', ' ')
                separator = "\t"
                cvssv3 = ""
                cvssv2 = ""
                cvssv3_missing = False
                cvssv2_missing = False
                try:
                    cvssv3 = separator.join([cves['impact']['baseMetricV3']['cvssV3']['attackComplexity'], cves['impact']['baseMetricV3']['cvssV3']['attackVector'], cves['impact']['baseMetricV3']['cvssV3']['availabilityImpact'], cves['impact']['baseMetricV3']['cvssV3']['confidentialityImpact'], cves['impact']['baseMetricV3']['cvssV3']['integrityImpact'], cves['impact']['baseMetricV3']['cvssV3']['privilegesRequired'], cves['impact']['baseMetricV3']['cvssV3']['scope'], cves['impact']['baseMetricV3']['cvssV3']['userInteraction'], cves['impact']['baseMetricV3']['cvssV3']['vectorString'], str(cves['impact']['baseMetricV3']['exploitabilityScore']), str(cves['impact']['baseMetricV3']['impactScore']), str(cves['impact']['baseMetricV3']['cvssV3']['baseScore']), str(cves['impact']['baseMetricV3']['cvssV3']['baseSeverity'])])
                except Exception as e:
                    if str(e) == "'baseMetricV3'":
                        cvssv3_missing = True
                        cvssv3 = separator.join(["", "", "", "", "", "", "", "", "", "", "", "", ""])
                    else:
                        print(str(e))
                try:
                    cvssv2 = separator.join([cves['impact']['baseMetricV2']['cvssV2']['accessComplexity'], cves['impact']['baseMetricV2']['cvssV2']['accessVector'], cves['impact']['baseMetricV2']['cvssV2']['authentication'], cves['impact']['baseMetricV2']['cvssV2']['availabilityImpact'], cves['impact']['baseMetricV2']['cvssV2']['confidentialityImpact'], cves['impact']['baseMetricV2']['cvssV2']['integrityImpact'], str(cves['impact']['baseMetricV2']['obtainAllPrivilege']), str(cves['impact']['baseMetricV2']['obtainOtherPrivilege']), str(cves['impact']['baseMetricV2']['obtainUserPrivilege']), str(cves['impact']['baseMetricV2']['userInteractionRequired']), cves['impact']['baseMetricV2']['cvssV2']['vectorString'], str(cves['impact']['baseMetricV2']['exploitabilityScore']), str(cves['impact']['baseMetricV2']['impactScore']), str(cves['impact']['baseMetricV2']['cvssV2']['baseScore']), str(cves['impact']['baseMetricV2']['severity'])])
                except Exception as e:
                    if str(e) == "'baseMetricV2'":
                        cvssv2 = separator.join(["", "", "", "", "", "", "", "", "", "", "", "", ""])
                        cvssv2_missing = True
                    elif str(e) == "'userInteractionRequired'":
                        cvssv2 = separator.join([cves['impact']['baseMetricV2']['cvssV2']['accessComplexity'], cves['impact']['baseMetricV2']['cvssV2']['accessVector'], cves['impact']['baseMetricV2']['cvssV2']['authentication'], cves['impact']['baseMetricV2']['cvssV2']['availabilityImpact'], cves['impact']['baseMetricV2']['cvssV2']['confidentialityImpact'], cves['impact']['baseMetricV2']['cvssV2']['integrityImpact'], str(cves['impact']['baseMetricV2']['obtainAllPrivilege']), str(cves['impact']['baseMetricV2']['obtainOtherPrivilege']), str(cves['impact']['baseMetricV2']['obtainUserPrivilege']), "", cves['impact']['baseMetricV2']['cvssV2']['vectorString'], str(cves['impact']['baseMetricV2']['exploitabilityScore']), str(cves['impact']['baseMetricV2']['impactScore']), str(cves['impact']['baseMetricV2']['cvssV2']['baseScore']), str(cves['impact']['baseMetricV2']['severity'])])
                    else:
                        print(str(e))
                if cvssv2_missing and cvssv3_missing:
                    #print "Both CVSSv2 and CVSSv3 are missing"
                    file_cvss_score.write(f"{cve}\t{cvssv3}\t{cvssv2}\t\t\t{description}\t{cves['publishedDate']}\t{cves['lastModifiedDate']}\n")
                    # file_cvss_score.write(f"{cve.encode('utf-8')}\t{cvssv3}\t{cvssv2.encode('utf-8')}\t\t\t{description.encode('utf-8')}\t{cves['publishedDate'].encode('utf-8')}\t{cves['lastModifiedDate'].encode('utf-8')}\n")
                    # file_cvss_score.write(cve.encode('utf-8')+"\t"+cvssv3+"\t"+cvssv2.encode('utf-8')+"\t"+"\t"+"\t"+description.encode('utf-8')+"\t"+cves['publishedDate'].encode('utf-8')+"\t"+cves['lastModifiedDate'].encode('utf-8')+"\n")
                else:
                    file_cvss_score.write(f"{cve}\t{cvssv3}\t{cvssv2}\t{description}\t{cves['publishedDate']}\t{cves['lastModifiedDate']}\n")
                    # file_cvss_score.write(f"{cve.encode('utf-8')}\t{cvssv3.encode('utf-8')}\t{cvssv2.encode('utf-8')}\t{description.encode('utf-8')}\t{cves['publishedDate'].encode('utf-8')}\t{cves['lastModifiedDate'].encode('utf-8')}\n")
                    # file_cvss_score.write(cve.encode('utf-8')+"\t"+cvssv3.encode('utf-8')+"\t"+cvssv2.encode('utf-8')+"\t"+description.encode('utf-8')+"\t"+cves['publishedDate'].encode('utf-8')+"\t"+cves['lastModifiedDate'].encode('utf-8')+"\n")
            for problem_type in cves['cve']['problemtype']['problemtype_data']:
                for descr in problem_type['description']:
                    problem = descr['value']
                    if csv:
                        # file_cve_related_problems.write(cve+"\t"+problem+"\n")
                        #print(cvssv3_missing, cvssv2_missing, cves['impact'])
                        file_cve_related_problems.write(f"{cve}\t{problem}\t{cves['publishedDate']}")
                        if cves['impact']:
                            if cves['impact'].get('baseMetricV2'): 
                                file_cve_related_problems.write(f"\t{cves['impact']['baseMetricV2']['severity']}\t{cves['impact']['baseMetricV2']['impactScore']}\n")
                            elif cves['impact'].get('baseMetricV3'):
                                file_cve_related_problems.write(f"\t{cves['impact']['baseMetricV3']['cvssV3']['baseSeverity']}\t{cves['impact']['baseMetricV3']['impactScore']}\n")
                            else:
                                print("baseMetricV3 NO baseMetricV2")
                                file_cve_related_problems.write("\t\t\n")
                        else:
                            print("No impact on cve: ", cve)
                            file_cve_related_problems.write("\t\t\n")
            try:
                cpe_list_length = len(cves['configurations']['nodes'])
                if (cpe_list_length != 0):
                    for i in range(0, cpe_list_length):
                        if 'children' in cves['configurations']['nodes'][i]:
                            cpe_child_list_length = len(cves['configurations']['nodes'][i]['children'])
                            if (cpe_child_list_length != 0):
                                for j in range(0, cpe_child_list_length):
                                    if('cpe_match' in cves['configurations']['nodes'][i]['children'][j]):
                                        cpes = cves['configurations']['nodes'][i]['children'][j]['cpe_match']
                                        for cpe in cpes:
                                            if csv:
                                                if 'cpe22Uri' in cpe:
                                                    file_cpes.write(cve+"\t"+cpe['cpe22Uri']+"\t"+cpe['cpe23Uri'].replace('cpe:2.3:o:','')+"\t"+str(cpe['vulnerable'])+"\n")
                                                if 'cpe23Uri' in cpe:
                                                    file_cpes.write(cve+"\t"+"\t"+cpe['cpe23Uri']+"\t"+str(cpe['vulnerable'])+"\n")
                        else:
                            if('cpe_match' in cves['configurations']['nodes'][i]):
                                cpes = cves['configurations']['nodes'][i]['cpe_match']
                                for cpe in cpes:
                                    if csv:
                                        if 'cpe22Uri' in cpe:
                                            file_cpes.write(cve+"\t"+cpe['cpe22Uri']+"\t"+cpe['cpe23Uri'].replace('cpe:2.3:o:','')+"\t"+str(cpe['vulnerable'])+"\n")
                                        if 'cpe23Uri' in cpe:
                                            file_cpes.write(cve+"\t"+"\t"+cpe['cpe23Uri']+"\t"+str(cpe['vulnerable'])+"\n")
                            else:
                                cpe_inner_list_length = len(cves['configurations']['nodes'])
                                if (cpe_inner_list_length != 0):
                                    for k in range(0, cpe_inner_list_length):
                                        if('cpe_match' in cves['configurations']['nodes'][i]):
                                            cpes = cves['configurations']['nodes'][i]['cpe_match']
                                            for cpe in cpes:
                                                if csv:
                                                    if 'cpe22Uri' in cpe:
                                                        file_cpes.write(cve+"\t"+cpe['cpe22Uri']+"\t"+cpe['cpe23Uri'].replace('cpe:2.3:o:','')+"\t"+str(cpe['vulnerable'])+"\n")
                                                    if 'cpe23Uri' in cpe:
                                                        file_cpes.write(cve+"\t"+"\t"+cpe['cpe23Uri']+"\t"+str(cpe['vulnerable'])+"\n")
            except Exception as e:
                print((str(e), cves['configurations'])) #check it
        file_cve_related_problems.close()
        file_cvss_score.close()
        file_cpes.close()
    if import_db:
        print('Connecting to the PostgreSQL database...')
        with connect(dbname=database, user=myuser, host=myhost, password=mypassword) as con:
            with con.cursor() as cur:
                filename = results+"cve_cvss_scores.csv"
                with open(filename, 'r', encoding="utf-8") as f:
                    print("importing CVSS")
                    filedata = f.read()
                    filedata = filedata.replace("\\", "\\\\")
                    output = io.StringIO()
                    output.write(filedata)
                    output.seek(0)
                    output.readline()
                    cur.copy_from(output, 'cvss', sep='\t', null="")
                con.commit()
                f.close()
                '''
                filename = results+"cve_related_problems.csv"
                with open(filename, 'r') as f:
                    print("importing CVE-related problems")
                    f.readline()
                    cur.copy_from(f, 'cve_problem', sep='\t',columns=('cve', 'problem'))
                con.commit()
                f.close()
                '''
                filename = results+"cve_cpes.csv"
                with open(filename, 'r', encoding="utf-8") as f:
                    print("importing CVEs vs CPEs")
                    f.readline()
                    cur.copy_from(f, 'cpe', sep='\t', columns=('cve', 'cpe22uri', 'cpe23uri', 'vulnerable'))
                con.commit()
                f.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CVEs Manager.') # version='0.1'
    parser.add_argument('-p', '--parse',  action="store_true", dest="process", default=False, help="Process downloaded CVEs.")
    parser.add_argument('-d', '--download',  action="store_true", dest="download", default=False, help="Download CVEs.")
    parser.add_argument('-y', '--year',  action="store", dest="year", default=False, help="The year for which CVEs shall be downloaded (e.g. 2019)")
    parser.add_argument('-csv', '--cvs_files',  action="store_true", dest="csv", default=False, help="Create CSVs files.")
    parser.add_argument('-idb', '--import_to_db',  action="store_true", dest="idb", default=False, help="Import CVEs into a database.")
    parser.add_argument('-i', '--input', action="store", default = 'nvd/', dest="input", help="The directory where NVD json files will been downloaded, and the one from where they will be parsed (default: nvd/")
    parser.add_argument('-o', '--output', action="store", default = 'results/', dest="results", help="The directory where the csv files will be stored (default: results/")
    parser.add_argument('-u', '--user',  action="store", dest="user", default="postgres", help="The user to connect to the database.")
    parser.add_argument('-ow', '--owner',  action="store", dest="owner", default=None, help="The owner of the database (if different from the connected user).")
    parser.add_argument('-ps', '--password',  action="store", dest="password", default="", help="The password to connect to the database.")
    parser.add_argument('-host', '--host',  action="store", dest="host", default="localhost", help="The host or IP of the database server.")
    parser.add_argument('-db', '--database',  action="store", dest="database", default="postgres", help="The name of the database.")
    parser.add_argument('-cd', '--create_database',  action="store_true", dest="cd", default=False, help="Create the database")
    parser.add_argument('-dd', '--drop_database',  action="store_true", dest="dd", default=False, help="Drop the database")
    parser.add_argument('-ct', '--create_tables',  action="store_true", dest="ct", default=False, help="Create the tables of the database")
    parser.add_argument('-tr', '--truncate_cves_tables',  action="store_true", dest="tr", default=False, help="Truncate the CVEs-related tables")
    parser.add_argument('-cve', '--cvs_number',  action="store", dest="cve", default=None, help="Print info for a CVE (CVSS score and other)")
    parser.add_argument('-sc', '--score',  action="store", dest="score", default=0.0, help="Use base score of a CVE as a selection criterion")
    parser.add_argument('-dt', '--date',  action="store", dest="date", default=1999, help="Use publication date of a CVE as a selection criterion")
    values = parser.parse_args()

    if not values.owner:
        values.owner = values.user
    if values.dd:
        db.drop_database(values.user, values.password, values.host, values.database)
    if values.cd:
        db.create_database(values.user, values.password, values.host, values.database, values.owner)
    if values.ct:
        db.create_tables(values.user, values.password, values.host, values.database)
    if values.download:
        download_cves(values.input, values.year)
    if values.process:
        process_cves(values.input, values.results, values.csv, values.idb, values.user, values.password, values.host, values.database)
    if values.tr: 
        db.truncate_database(values.user, values.password, values.host, values.database)
    if values.cve:
        db.execute_query(values.user, values.password, values.host, values.database, values.cve, values.score, values.date)
    if not values.input and not values.process and not values.dd and not values.cd and not values.ct and not values.download and not values.process and not values.tr and not values.cve:
        print("Choose an option (check --help)")

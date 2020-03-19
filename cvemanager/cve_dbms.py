import psycopg2
from psycopg2 import connect
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

create_tables_query = '''
--
-- Name: cvss; Type: TABLE; Schema: public; Owner: atlas
--
CREATE TABLE public.cvss (
    cve character(20) NOT NULL,
    attack_complexity_3 character(5),
    attack_vector_3 character(20),
    availability_impact_3 character(5),
    confidentiality_impact_3 character(5),
    integrity_impact_3 character(5),
    privileges_required_3 character(5),
    scope_3 character(10),
    user_interaction_3 character(10),
    vector_string_3 character(50),
    exploitability_score_3 real,
    impact_score_3 real,
    base_score_3 real,
    base_severity_3 character(10),
    access_complexity character(10),
    access_vector character(20),
    authentication character(10),
    availability_impact character(10),
    confidentiality_impact character(10),
    integrity_impact character(10),
    obtain_all_privileges boolean,
    obtain_other_privileges boolean,
    obtain_user_privileges boolean,
    user_interaction_required boolean,
    vector_string character(50),
    exploitability_score real,
    impact_score real,
    base_score real,
    severity character(10),
    description text,
    published_date date,
    last_modified_date date
);
--ALTER TABLE public.cvss OWNER TO atlas;

--
-- Name: cpe; Type: TABLE; Schema: public; Owner: atlas
--
CREATE TABLE public.cpe (
    cve character(20) NOT NULL,
    cpe22uri text,
    cpe23uri text,
    vulnerable character(5)
);
--ALTER TABLE public.cpe OWNER TO atlas;

--
-- Name: cve_problem; Type: TABLE; Schema: public; Owner: atlas
--
CREATE TABLE public.cve_problem (
    cve character(20) NOT NULL,
    problem text
);
--ALTER TABLE public.cve_problem OWNER TO atlas;

--
-- Name: cvss_vs_cpes; Type: VIEW; Schema: public; Owner: atlas
--
CREATE VIEW public.cvss_vs_cpes AS
 SELECT cvss.cve,
    cvss.base_score_3,
    cvss.base_severity_3,
    cvss.base_score,
    cvss.severity,
    cpe.cpe23uri,
    cvss.description
   FROM public.cpe,
    public.cvss
  WHERE (cpe.cve = cvss.cve);
--ALTER TABLE public.cvss_vs_cpes OWNER TO atlas;
'''

def create_database(myuser, mypassword, myhost, database, owner):
    with connect(dbname="postgres", user=myuser, host=myhost, password=mypassword) as con:
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        with con.cursor() as cur:
            try:
                cur.execute(sql.SQL("CREATE DATABASE {} ;").format(sql.Identifier(database)))
                print("Database", database, "was created.")
                cur.execute(sql.SQL("ALTER DATABASE {} OWNER TO {};").format(sql.Identifier(database), sql.Identifier(owner)))
                print("Owner of the database changed to:", owner)
            except (Exception, psycopg2.DatabaseError) as error:
                print("Error while creating database", error)
        con.commit()

def create_tables(myuser, mypassword, myhost, database):
    with connect(dbname=database, user=myuser, host=myhost, password=mypassword) as con:
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        with con.cursor() as cur:
            try:
                cur.execute(create_tables_query)
                print("Tables and Views created successfully for database: ", database)
            except (Exception, psycopg2.DatabaseError) as error:
                print("Error while creating tables", error)
        con.commit()

def drop_database(myuser, mypassword, myhost, database):
    with connect(dbname="postgres", user=myuser, host=myhost, password=mypassword) as con:
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        with con.cursor() as cur:
            try:
                cur.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(database)))
                print("Database", database, "was dropped.")
            except (Exception, psycopg2.DatabaseError) as error:
                print("Error while dropping PostgreSQL Database", error)
        con.commit()

def truncate_database(myuser, mypassword, myhost, database):
    with connect(dbname=database, user=myuser, host=myhost, password=mypassword) as con:
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        with con.cursor() as cur:
            print("Truncating CVEs tables")
            try:
                cur.execute("Truncate cpe, cve_problem, cvss;")
            except (Exception, psycopg2.DatabaseError) as error:
                print("Error while Truncating PostgreSQL Database", error)
        con.commit()


def execute_query(myuser, mypassword, myhost, database, cve, score, date):
    query = "SELECT cve, vector_string_3, base_score_3, base_severity_3, vector_string, base_score, severity, description, published_date FROM cvss WHERE base_score_3 > %s AND date_part('year', published_date) >= %s"

    if cve:
        query = query + " AND cve LIKE %s"


    with connect(dbname=database, user=myuser, host=myhost, password=mypassword) as con:
        with con.cursor() as cur:
            print("Executing query")
            try:
                if cve:
                    cve = '%' + cve + '%'
                    cur.execute(query, (score, date, cve))
                else:
                    cur.execute(query, (score, date))
                selected_cve = cur.fetchone()
                answer = ""
                for r in selected_cve:
                    if type(r) is str:
                        answer = answer + r.strip() + "\t"
                    else:
                        answer = answer + str(r) + "\t"
                answer = answer.rstrip('\t')
                print(answer)
            except(Exception, psycopg2.DatabaseError) as error:
                print("Error while Querying Database", error)

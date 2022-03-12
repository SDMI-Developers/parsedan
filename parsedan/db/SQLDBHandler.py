from sqlalchemy.orm import Session
import datetime
import json
import logging
import multiprocessing
import threading
import time
from sqlalchemy import create_engine
from typing import List
import logging
import sqlalchemy
from sqlalchemy.orm import sessionmaker
from parsedan.Nist import Nist
from parsedan.db.sqlmodels import CVE, Base, CVEHistory, Computer, ParsedFile, PortHistory, Job
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy import inspect
from sqlalchemy.orm import scoped_session
from multiprocessing.pool import ThreadPool
logger = logging.getLogger(__name__)


def multi_run_wrapper(args):
    return _multi_calculate_scores(*args)


def _multi_calculate_scores(offset: int, limit: int, connection_string: str, nist_cve_cache: dict, q: multiprocessing.Queue):
    """ Function to calculate scores.
    Must be outside of the class due to pickling

    Args:
        offset (int): Offset of DB
        limit (int): Limit of DB
        connection_string (str): Connection string to db
        nist_cve_cache (dict): the cve cache (use a manager dict)
        q (multiprocessing.Queue):

    """
    q.put(0)

    # Connect to the database
    dbhandler = DBHandler(connection_string)

    # Query all the computers
    query: List[Computer] = dbhandler.session.query(
        Computer).order_by(Computer.ip).offset(offset).limit(limit)

    computers = {}

    for computer in query:
        computers[computer.ip] = {}
        computers[computer.ip]["instance"] = computer
        computers[computer.ip]["port_history"] = []
        computers[computer.ip]["cve_history"] = []

    ip_list = list(computers.keys())
    q2 = dbhandler.session.query(PortHistory).filter(
        PortHistory.computer_id.in_(ip_list))
    q3 = dbhandler.session.query(CVEHistory).filter(
        CVEHistory.computer_id.in_(ip_list))

    for cve in q3:
        computers[cve.computer_id]["cve_history"].append(cve)

    for port in q2:
        computers[port.computer_id]["port_history"].append(port)
    # Call calculate score for each comp
    for comp in computers.values():
        computer: Computer = comp["instance"]
        cves: List[CVEHistory] = comp["cve_history"]
        ports: List[PortHistory] = comp["port_history"]
        computer.score = dbhandler._calculate_score(
            computer, cves, ports, nist_cve_cache)
    dbhandler.session.commit()

    # Disconnect the db from this core
    dbhandler._disconnect()


class DBHandler:
    """ Handles anything that happens to the database.
    Makes it super easy to go from one db engine to the next for testing
    purposes (mongo/sqlalchemy)
    """
    support_multi_core = True

    def __init__(self, db_connection_string: str = None, check_nist_up_to_date: bool = True):
        self.db_connection_string = db_connection_string
        self._connect_to_db()
        self.nist = Nist(self)

        if check_nist_up_to_date:
            # Make sure CVE data is up-to-date
            self.nist.check_cve_modified()

    def _connect_to_db(self):
        engine = create_engine(self.db_connection_string)
        Base.metadata.create_all(engine)

        session_factory = sessionmaker(bind=engine)
        Session = scoped_session(session_factory)
        self.engine = engine
        self.session = Session()
        self.Session = Session

    def _disconnect(self):
        self.session.close()
        self.engine.dispose()

    def _clear_db(self):
        """
        Call this function if you want to clear the database
        """
        logger.info("Clearing the database")
        engine = self.engine
        logger.debug("Dropping all tables")
        Base.metadata.drop_all(engine)

        logger.debug("Recreating all tables")
        Base.metadata.create_all(engine)
        self.session.commit()

    def upsert_objects(self, db_class, values: list):
        if len(values) == 0:
            return

        updated = 0
        created = 0

        # Max items to allow per "flush" session
        MAX_ITEMS = 10000
        for i in range(0, len(values), MAX_ITEMS):
            logger.debug(f"Executing: {i}/{len(values)}")

            # Get the primary keys that are part of the table
            primary_keys = [key.name for key in inspect(db_class).primary_key]

            # Define the insert statement
            stmt = insert(db_class).values(values[i:i+MAX_ITEMS])
            # stmt = insert(db_class).returning(
            #     sqlalchemy.column("xmax") == 0
            # ).values(values[i:i+MAX_ITEMS])

            # define dict of non-primary keys for updating
            update_dict = {
                c.name: c
                for c in stmt.excluded
                if not c.primary_key
            }

            # Nothing to update if dict empty (primary key shouldnt update!)
            if len(update_dict.keys()) > 0:
                stmt = stmt.on_conflict_do_update(
                    index_elements=primary_keys,
                    # The columns that should be updated on conflict
                    set_=update_dict
                )
            else:
                # Do nothing
                stmt = stmt.on_conflict_do_nothing(
                    index_elements=primary_keys
                )

            # Execute the changes
            self.session.execute(stmt)
            # Figure out created vs updated
            results = self.session.execute(stmt)
            # for _ in results:
            #     if _[0]:
            #         created += 1
            #     else:
            #         updated += 1
            self.session.flush()

        # print(f"Created: {created} Updated: {updated}")

    def save_parsed_file(self, file_md5: str, json_file_loc: str):
        """ Save the given md5/loc to the db so we can tell if
        a file has been parsed before.

        Args:
            file_md5 (str): MD5 of the file
            json_file_loc (str): Location of the file
        """
        logger.debug("Creating parsed file")
        parsed_file = ParsedFile()
        parsed_file.datetime_parsed = datetime.datetime.now()
        parsed_file.file_md5 = file_md5
        parsed_file.filename = json_file_loc
        logger.debug("Committing parsed file")
        self.session.add(parsed_file)
        self.session.commit()

    def is_file_parsed(self, file_md5: str) -> bool:
        """
        Determines whether a file was already parsed in the DB by checking the MD5 value against existing DB entries.

        Args:
            file_md5 (str): The MD5 value of the json file.
        Returns:
            bool: Whether the file is already parsed are not
        """
        logger.info(f"Checking if file already parsed. {file_md5}")
        file = self.session.query(ParsedFile).filter(
            ParsedFile.file_md5 == file_md5).first()
        if file:
            logger.debug("Already parsed!")
            return True
        logger.debug("Not parsed yet!")
        return False

    def get_computers(self, offset, limit) -> List[Computer]:
        return self.session.query(Computer).options(sqlalchemy.orm.selectinload(Computer.cve_history), sqlalchemy.orm.selectinload(Computer.port_history)).offset(offset).limit(limit).all()

    def get_dates(self):
        cve_dates = self.session.query(
            CVEHistory.date_observed).distinct(CVEHistory.date_observed)
        cve_dates = [r.date_observed for r in cve_dates]

        port_dates = self.session.query(
            PortHistory.date_observed).distinct(PortHistory.date_observed)
        port_dates = [r.date_observed for r in port_dates]
        
        return (cve_dates, port_dates)

    def _calculate_scores(self):

        logger.info("Calculating scores")
        start = time.time()

        LIMIT_AMT = 12000

        start = time.time()
        row_count = self.session.query(Computer).count()
        # p = ThreadPool(4)
        p = multiprocessing.Pool(multiprocessing.cpu_count() - 1)
        m = multiprocessing.Manager()
        q = m.Queue()

        # Cache of cve's from nist
        nist_cve_cache = m.dict()

        # Make sure limit is never greater then row
        if LIMIT_AMT > row_count:
            LIMIT_AMT = row_count

        if self.support_multi_core:
            # Build jobs for each process
            jobs = []
            for i in range(0, row_count, LIMIT_AMT):
                jobs.append(
                    (i, LIMIT_AMT, self.db_connection_string, nist_cve_cache, q))

            results = p.map_async(multi_run_wrapper, jobs).get()

            logger.debug(f"Time to calculate scores: {time.time() - start}")

            p.close()
        else:
            logger.error("Miltiprocessless support not implemented")

    def _calculate_score(self, computer: Computer, cves: List[CVEHistory], ports: List[PortHistory], cvss_cache: dict) -> float:
        """ Calculates score for a given computer
        Args:
            computer (VulnerableComputer): Computer to calculate score for.
            cves (List[CVEHistory]): List of CVE's that belong to that computer
            ports (List[PortHistory],): List of ports that belong to that computer

        Returns:
            float: The score that was calculated.
        """

        # Sort dates Newest to oldest
        ports = sorted(
            ports, key=lambda x: x.date_observed, reverse=True)

        # Getting the most current date of port history
        most_current_date = ports[0].date_observed

        range_date = most_current_date - datetime.timedelta(days=5)

        # Only include ports/cves for the past 5 days.
        ports = list(filter(lambda x: x.date_observed >= range_date, ports))
        cves = list(filter(lambda x: x.date_observed >= range_date, cves))

        date_added = computer.date_added

        # TODO: Define what vulnerable means (like only count number of days vuln if contains bad port open)

        # Getting unique ports
        distinct_ports = set()
        for port in ports:
            if port.port not in distinct_ports:
                distinct_ports.add(port.port)

        # Basically if no CVE's and ONLY 443/80 open then 0 score
        if len(cves) == 0:
            if len(distinct_ports) == 1:
                if 80 in distinct_ports or 443 in distinct_ports:
                    return 0

            if len(distinct_ports) == 2:
                if 80 in distinct_ports and 443 in distinct_ports:
                    return 0

        num_days_vuln = (most_current_date - date_added).days

        num_days_vuln_score = 10 / 10
        if num_days_vuln < 1:  # FRESH COMPUTER HIGH ALERT
            num_days_vuln_score = 10 / 10
        elif num_days_vuln < 7:
            num_days_vuln_score = 9 / 10
        elif num_days_vuln < 14:
            num_days_vuln_score = 5 / 10
        elif num_days_vuln > 30:
            num_days_vuln_score = 10 / 10

        score = num_days_vuln_score * 0.1

        # TODO: List and rank open ports
        # Num of open ports section 10%

        num_open_ports = len(distinct_ports)
        num_ports_score = 10 / 10

        if num_open_ports < 2:
            num_ports_score = 1 / 10
        elif num_open_ports < 4:
            num_ports_score = 5 / 10
        elif num_open_ports < 10:
            num_ports_score = 10 / 10

        score += num_ports_score * 0.1

        # Num of cves section 10%
        # Getting unique cves
        distinct_cves = set()
        cvssScores = []

        for cve in cves:
            # Create a set of unique cve names
            if cve.cve_name not in distinct_cves:
                distinct_cves.add(cve.cve_name)
            cve_name = cve.cve_name

            # Fetch cvss scores for each cve
            if cve_name not in cvss_cache:
                try:
                    cvss_cache[cve_name] = self.session.query(
                        CVE).get(cve_name)
                except Exception:
                    print(f"Couldnt find that CVE {cve_name}")
                    logger.debug(f"Couldnt find that CVE {cve_name}")
                    continue

            cve: CVE = cvss_cache[cve_name]
            if cve.cvss_30:
                cvssScores.append(cve.cvss_30)
            elif cve.cvss_20:
                cvssScores.append(cve.cvss_20)

        numOfCVES = len(distinct_cves)
        if numOfCVES == 0:
            numOfCVESScore = 0 / 10
        elif numOfCVES < 2:
            numOfCVESScore = 8 / 10
        elif numOfCVES < 4:
            numOfCVESScore = 9 / 10
        else:
            numOfCVESScore = 10 / 10
        score += numOfCVESScore * 0.1

        # CVSS Scoring (15% Avg/35% Highest)
        cvssScoresLen = len(cvssScores)
        if cvssScoresLen > 0:
            cvssAvg = sum(cvssScores) / len(cvssScores)
            cvssMax = max(cvssScores)
            score += (cvssAvg / 10) * 0.15
            score += (cvssMax / 10) * 0.35

        score += 0.20
        return score * 100

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
from parsedan.db.sqlmodels import CVE, Base, CVEHistory, Computer, PortHistory
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy import inspect
from sqlalchemy.orm import scoped_session
from multiprocessing.pool import ThreadPool
logger = logging.getLogger(__name__)


def multi_run_wrapper(args):
    return multi(*args)


def multi(offset, limit, connection_string):
    dbhandler = DBHandler(connection_string)
    query = dbhandler.session.query(Computer).offset(offset).limit(
        limit).options(sqlalchemy.orm.selectinload(Computer.cve_history))
    total = 0
    for comp in query:
        total += len(comp.cve_history)

    # print(offset, limit, total)
    dbhandler._disconnect()
    print(f"Done: {offset+limit}", end="\r")


class DBHandler:
    """ Handles anything that happens to the database.
    Makes it super easy to go from one db engine to the next for testing
    purposes (mongo/sqlalchemy)
    """

    def __init__(self, db_connection_string: str = None):
        self.db_connection_string = db_connection_string
        self._connect_to_db()

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
        Call this function if you want to clear the database but don't want to delete any of the downloaded
        CVE data
        """
        pass

    def save_cve_to_json(self, json_file_loc):
        """Saves the CVE table from the database to a file.
        Useful if you want to reuse it in a new in-memory db
        without redownloading all of the information.

        Args:
            json_file_loc (_type_): Location to save json file
        """
        pass

    def load_cve_json(self, json_file_loc):
        """
        Loads the json of CVE's into the database.
        Useful for when you are running an in-memory db.

        Args:
            json_file_loc (_type_): Location of json file
        """
        self.session.query(CVE).delete()
        file_data = []
        # Loading or Opening the json file
        try:
            logger.info(f"Loading cve json file. {json_file_loc}")
            cve_load_start_time = time.time()
            with open(json_file_loc, 'r') as file:
                i = 0
                for line in file:
                    print(i, end="\r")
                    i += 1
                    line = json.loads(line)
                    cve = CVE()

                    line["lastModifiedDate"] = datetime.datetime.fromtimestamp(float(line["lastModifiedDate"]["$date"]) / 1000,
                                                                               datetime.timezone.utc)
                    line["publishedDate"] = datetime.datetime.fromtimestamp(float(line["publishedDate"]["$date"]) / 1000,
                                                                            datetime.timezone.utc)

                    cve.last_modified_date = line["lastModifiedDate"]
                    cve.published_date = line["publishedDate"]

                    if "cvss20" in line:
                        cve.cvss_20 = line["cvss20"]

                    if "cvss30" in line:
                        cve.cvss_30 = line["cvss30"]

                    cve.cve_name = line["_id"]

                    file_data.append(cve)

                logger.info("inserting cve's into database")

                logger.debug(
                    f"Time to load CVES: {time.time() - cve_load_start_time}")
                self.session.bulk_save_objects(file_data)
                self.session.commit()

                # Make CVE's from file are up to date.
                # self.check_cve_modified()
        except FileNotFoundError:
            logger.info("CVE file not found, ignoring call")
        except Exception as e:
            logger.exception(f"Unhandled error! {e}")

    def check_cve_modified(self):
        pass

    def upsert_objects(self, db_class, values: list):
        if len(values) == 0:
            return

        updated = 0
        created = 0

        # Max items to allow per "flush" session
        MAX_ITEMS = 10000
        for i in range(0, len(values), MAX_ITEMS):
            print(f"Executing: {i}/{len(values)}", end="\r")

            # Get the primary keys that are part of the table
            primary_keys = [key.name for key in inspect(db_class).primary_key]

            # Define the insert statement
            stmt = insert(db_class).returning(
                sqlalchemy.column("xmax") == 0
            ).values(values[i:i+MAX_ITEMS])

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
            self.session.execute(stmt)
            # Figure out created vs updated
            results = self.session.execute(stmt)
            for _ in results:
                if _[0]:
                    created += 1
                else:
                    updated += 1
            self.session.flush()

        print(f"Created: {created} Updated: {updated}")

    def recreate_cve_table(self, _modify: bool = None):
        """
        Will download one by one all files from nist.gov and
        save them into the db.
        """
        pass

    def save_nist_cve_to_db(self, nvdNistGzJsonURL: str):
        """
        :param nvdNistGzJsonURL: URL of gzipped nist file.
        :return: None if json failed to parse, else return results of
        mongoengine insert
        """
        pass

    def save_parsed_file(self, file_md5: str, json_file_loc: str):
        """ Save the given md5/loc to the db so we can tell if
        a file has been parsed before.

        Args:
            file_md5 (str): MD5 of the file
            json_file_loc (str): Location of the file
        """
        pass

    def _calculate_scores(self):

        logger.info("Calculating scores")
        start = time.time()

        # Holds our cvss data so it can be passed around and not reloaded
        cvss_cache = {}
        tot = 0
        operations = []

        # for i in range(0, row_count, LIMIT_AMT):
        #     start = time.time()
        #     tot += x(i+LIMIT_AMT, LIMIT_AMT)
        #     print(f"{time.time() - start} {tot}")
        # self.session.close()
        # self.engine.dispose()

        # s = 1000
        # p = 3
        # ps = []

        # start = time.time()
        # x(0, s*4, self.Session)
        # print(f"{time.time() - start}")

        # Amount to calculate scores for at a time
        LIMIT_AMT = 1000

        row_count = 50000  # self.session.query(Computer).count()
        jobs = []
        for i in range(0, row_count, LIMIT_AMT):
            jobs.append((i, LIMIT_AMT, self.db_connection_string))
        start = time.time()
        p = ThreadPool(3)
        #p = multiprocessing.Pool(4)
        p.map_async(multi_run_wrapper, jobs).get()
        print(f"{time.time() - start}")
        p.close()

        start = time.time()
        for i in range(0, row_count, LIMIT_AMT):
            multi(i, LIMIT_AMT, self.db_connection_string)
        print(f"{time.time() - start}")

        # self.session.close()
        # self.engine.dispose()
        # start = time.time()

        # print(f"{time.time() - start}")

        # cmps: List[VulnerableComputer] = VulnerableComputer.objects(
        #     pk__in=ip_list).skip(i).limit(LIMIT_AMT)

        # for comp in cmps:
        #     score = self._calculate_score(comp, cvss_cache)
        #     # Updating highscore
        #     if score > comp.high_score:
        #         comp.high_score = score
        #     comp.current_score = score
        #     computer_dict = comp._data

        #     # Remove these children as it doesnt matter if it exists or not
        #     # If i dont remove it, id have to do _data on them as well
        #     del computer_dict["port_history"]
        #     del computer_dict["cve_history"]
        #     # Adding this to our bulk operations
        #     operations.append(UpdateOne({"_id": comp.ip}, {
        #                       "$set": computer_dict}, upsert=True))

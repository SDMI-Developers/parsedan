import datetime
import json
import logging
import time
from typing import List, Union
from parsedan import Utility
from parsedan.db.mongomodels import CVE, ParsedFile, VulnerableComputer
from pymongo.results import BulkWriteResult
import mongoengine
from pymongo import UpdateOne
from dateutil import parser
from gzip import decompress
from typing import List
from netaddr import IPNetwork
from dateutil import parser
from pymongo import UpdateOne
from requests import get
import logging
from parsedan.Utility import Utility
from parsedan.db.mongomodels import *
from bson.json_util import loads, dumps, DEFAULT_JSON_OPTIONS

logger = logging.getLogger(__name__)


class DBHandler:
    """ Handles anything that happens to the database.
    Makes it super easy to go from one db engine to the next for testing
    purposes (mongo/sqlalchemy)
    """

    def __init__(self, db_connection_string: str = None) -> None:
        if db_connection_string:
            self.db_connection_string = db_connection_string
            self._connect_to_db()
        else:
            # TODO: In-Memory/SQLITE parse here
            logger.error("IN_MEMORY_NOT_IMPLEMENTED!")

    def _connect_to_db(self):
        logger.info(
            f"connecting to db with string {self.db_connection_string}")
        mongoengine.connect(host=self.db_connection_string)

    def _clear_db(self):
        """
        Call this function if you want to clear the database but don't want to delete any of the downloaded
        CVE data
        """
        VulnerableComputer.drop_collection()
        ParsedFile.drop_collection()
        return

    def save_cve_to_json(self, json_file_loc):
        """Saves the CVE table from the database to a file.
        Useful if you want to reuse it in a new in-memory db
        without redownloading all of the information.

        Args:
            json_file_loc (_type_): Location to save json file
        """
        try:
            logger.info(f"Opening output stream {json_file_loc}")
            with open(json_file_loc, 'w') as f:
                cves = CVE.objects
                for cve in cves:
                    v = json.loads(cve.to_json())
                    f.write(json.dumps(v) + "\n")
        except Exception:
            logger.exception(
                "Unabled to save CVE file, will have to manually be redownloaded.")

    def load_cve_json(self, json_file_loc):
        """
        Loads the json of CVE's into the database.
        Useful for when you are running an in-memory db.

        Args:
            json_file_loc (_type_): Location of json file
        """

        file_data = []
        # Loading or Opening the json file
        try:
            logger.info(f"Loading cve json file. {json_file_loc}")
            with open(json_file_loc, 'r') as file:
                for line in file:
                    line = json.loads(line)
                    line["lastModifiedDate"] = datetime.datetime.fromtimestamp(float(line["lastModifiedDate"]["$date"]) / 1000,
                                                                               datetime.timezone.utc)
                    line["publishedDate"] = datetime.datetime.fromtimestamp(float(line["publishedDate"]["$date"]) / 1000,
                                                                            datetime.timezone.utc)
                    file_data.append(line)

                logger.info("inserting cve's into database")
                cve_table = CVE._get_collection()
                cve_table.insert_many(file_data)

                # Make CVE's from file are up to date.
                self.check_cve_modified()
        except FileNotFoundError:
            logger.info("CVE file not found, ignoring call")
        except Exception as e:
            logger.exception(f"Unhandled error! {e}")

    def check_cve_modified(self):
        logger.info("Checking if CVE has been updated in the last 8 days.")

        # Checking if its been more then eight days since a cve was modified.
        # If so we need to rebuild our cve table
        last_modified: CVE = CVE.objects().order_by("-lastModifiedDate").first()
        rebuild_cve_db = True
        if last_modified:
            days = (datetime.datetime.today().date() -
                    last_modified.lastModifiedDate).days
            if days < 8:
                rebuild_cve_db = False

        if rebuild_cve_db:
            if last_modified is None:
                logger.debug("No CVE data exists. Downloading from nist!")
            else:
                logger.debug(
                    "Its been more then 8 days, Recreating nist table.")

            print("Downloading data from NIST.\nThis may take a few minutes!")

            # Recreate table with json dump
            self.recreate_cve_table(_modify=False)
        else:
            logger.info("Downloading modified fields from nist.gov")
            # Only add new and update modified fields to db.
            url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
            self.save_nist_cve_to_db(url)

        logger.info("Finished CVE checks... Up to date!")

    def recreate_cve_table(self, _modify: bool = None):
        """
        Will download one by one all files from nist.gov and
        save them into the db.
        """
        if not _modify:
            logger.info("\rDropping old CVE collection.")
            # Delete every item from table
            CVE.drop_collection()

        # TODO: Look into alive-progress to keep track of progress
        # https://github.com/rsalmei/alive-progress
        # Build url from year 2002 (nist records start at 2002) to today
        for year in range(2002, datetime.date.today().year + 1):
            url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
            logger.info(f"Downloading CVE-{year} from nist feeds.")

            if self.save_nist_cve_to_db(url) is None:
                logger.debug("NO CVE data saved")

    def save_nist_cve_to_db(self, nvdNistGzJsonURL: str):
        """
        :param nvdNistGzJsonURL: URL of gzipped nist file.
        :return: None if json failed to parse, else return results of
        mongoengine insert
        """
        JSON = Utility.get_gzipped_json(nvdNistGzJsonURL)
        if JSON is None:
            return None

        logger.info("Parsing CVE items")
        operations = []
        for cveItem in JSON["CVE_Items"]:
            cve: CVE = CVE()
            cve_name = cveItem["cve"]["CVE_data_meta"]["ID"]
            cve.cveName = cve_name
            if "baseMetricV2" in cveItem["impact"]:
                cve.cvss20 = cveItem["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            if "baseMetricV3" in cveItem["impact"]:
                cve.cvss30 = cveItem["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            cve.lastModifiedDate = parser.parse(cveItem["lastModifiedDate"])
            cve.publishedDate = parser.parse(cveItem["publishedDate"])
            cve_descriptions = cveItem["cve"]["description"]["description_data"]

            if len(cve_descriptions) > 0:
                cve.summary = cve_descriptions[0]["value"]

            operations.append(UpdateOne({"_id": cve_name}, {
                              "$set": cve._data}, upsert=True))

        logger.info("Inserting cvss's into db")
        return CVE._get_collection().bulk_write(operations)

    def save_parsed_file(self, file_md5: str, json_file_loc: str):
        """ Save the given md5/loc to the db so we can tell if
        a file has been parsed before.

        Args:
            file_md5 (str): MD5 of the file
            json_file_loc (str): Location of the file
        """
        parsed_file = ParsedFile()
        parsed_file.file_md5 = file_md5
        parsed_file.filename = json_file_loc
        parsed_file.datetime_parsed = datetime.datetime.now()
        parsed_file.save()

    def get_parsed_file(self, file_md5: str) -> Union[ParsedFile, None]:
        try:
            return ParsedFile.objects.get(file_md5=file_md5)
        except Exception as e:
            return None

    def _calculate_score(self, computer: VulnerableComputer, cvss_cache: dict) -> float:
        """ Calculates score for a given computer

        Args:
            computer (VulnerableComputer): Computer to calculate score for.

        Returns:
            float: The score that was calculated.
        """

        # Sort dates
        computer.port_history = sorted(
            computer.port_history, key=lambda x: x.date_observed, reverse=True)

        # Getting the most current date of port history
        most_current_date = computer.port_history[0].date_observed
        most_current_date = datetime.datetime.strptime(
            most_current_date, "%Y-%m-%d")

        range_date = most_current_date - datetime.timedelta(days=5)
        # print(range_date, most_current_date)

        # Only include ports/cves for the past 5 days.
        computer.port_history = list(filter(lambda x: datetime.datetime.strptime(x.date_observed, "%Y-%m-%d")
                                            >= range_date, computer.port_history))
        computer.cve_history = list(filter(lambda x: datetime.datetime.strptime(x.date_observed, "%Y-%m-%d")
                                           >= range_date, computer.cve_history))

        date_added = datetime.datetime.strptime(
            computer.date_added, "%Y-%m-%d")
        num_days_vuln = (most_current_date - date_added).days
        num_days_vuln_score = 10 / 10
        if num_days_vuln < 7:
            num_days_vuln_score = 8 / 10
        elif num_days_vuln < 14:
            num_days_vuln_score = 9 / 10
        score = num_days_vuln_score * 0.1

        # ToDo List and rank open ports

        # Num of open ports section 10%

        # Getting unique ports
        distinct_ports = set()
        for port_obj in computer.port_history:
            if port_obj.port not in distinct_ports:
                distinct_ports.add(port_obj.port)

        numOfPorts = len(distinct_ports)
        numOfPortsScore = 10 / 10
        if numOfPorts < 2:
            numOfPortsScore = 8 / 10
        elif numOfPorts < 4:
            numOfPortsScore = 9 / 10

        score += numOfPortsScore * 0.1

        # Num of cves section 10%
        # Getting unique cves
        distinct_cves = set()
        cvssScores = []
        for cve_obj in computer.cve_history:
            # Create a set of unique cve names
            if cve_obj.cveName not in distinct_cves:
                distinct_cves.add(cve_obj.cveName)
            cve_name = cve_obj.cveName

            # Fetch cvss scores for each cve
            if cve_name not in cvss_cache:
                try:
                    cvss_cache[cve_name] = CVE.objects.get(pk=cve_name)
                except mongoengine.errors.DoesNotExist:
                    continue

            cve: CVE = cvss_cache[cve_name]
            if cve.cvss30:
                cvssScores.append(cve.cvss30)
            elif cve.cvss20:
                cvssScores.append(cve.cvss20)

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

        # Important comp section 10%
        if computer.is_whitelisted:
            score += (10 / 10) * 0.10

        score += 0.10
        score *= 100

        return score

    def _calculate_scores(self, ip_list: List):
        """
        :param ip_list: List of IP addresses that have changed so they need there score recalculated.
        """

        if len(ip_list) == 0:
            logger.debug("Ip list empty")
            return

        # Amount to calculate scores for at a time
        LIMIT_AMT = 10000

        logger.info("Calculating scores")
        start = time.time()
        i = 0

        # Holds our cvss data so it can be passed around and not reloaded
        cvss_cache = {}
        tot = 0
        operations = []

        while i <= len(ip_list):
            cmps: List[VulnerableComputer] = VulnerableComputer.objects(
                pk__in=ip_list).skip(i).limit(LIMIT_AMT)
            for comp in cmps:
                score = self._calculate_score(comp, cvss_cache)
                # Updating highscore
                if score > comp.high_score:
                    comp.high_score = score
                comp.current_score = score
                computer_dict = comp._data

                # Remove these children as it doesnt matter if it exists or not
                # If i dont remove it, id have to do _data on them as well
                del computer_dict["port_history"]
                del computer_dict["cve_history"]
                # Adding this to our bulk operations
                operations.append(UpdateOne({"_id": comp.ip}, {
                                  "$set": computer_dict}, upsert=True))
            i += LIMIT_AMT
            tot += len(cmps)

        # Writing changes to db
        logger.debug(f"Saving scores to db")

        VulnerableComputer._get_collection().bulk_write(operations)
        logger.info(f"Done calculating scores! Time: {time.time() - start}")

    def save_computers(self, computers: dict):
        """ Save computer given in dictionary form to the db
        Will handle upserting into the db.

        Args:
            computers (dict): A dictionary of unique computer
        """
        logger.info("Saving data!")

        logger.debug("Building the DB query for insertion.")
        operations = []

        insert_data_time = time.time()

        if len(list(computers.keys())) == 0:
            logger.debug("Empty data given!")
            return

        for ip in computers:
            computer = computers[ip]["computer"]._data

            try:
                # If these arnt deleted the db will think its a new comp and overwrite old ones.
                del computer["port_history"]
                del computer["cve_history"]
                del computer["current_score"]
                del computer["high_score"]
            except KeyError:
                logger.debug("Already removed keys!")

            # Insert/Update parents first
            operations.append(
                UpdateOne({"_id": ip}, {"$set": computer}, upsert=True)
            )

            logger.debug("Flattening ports!")
            # Flattening ports into an array.
            for date in computers[ip]["ports"]:
                for port in computers[ip]["ports"][date]:
                    p = computers[ip]["ports"][date][port]
                    operations.append(UpdateOne({"_id": ip},
                                                {"$addToSet": {"port_history": p._data}}, upsert=True))

            # # Insert/Update cve history
            for cve in computers[ip]["cves"]:
                operations.append(UpdateOne({"_id": ip},
                                            {"$addToSet": {"cve_history": cve._data}}, upsert=True))

        logger.debug("Saving computers to database")

        result: BulkWriteResult = VulnerableComputer._get_collection().bulk_write(operations)

        logger.info(
            f"Done saving data! Time: {time.time() - insert_data_time} Added {result.upserted_count}, Updated {result.modified_count}")

        self._calculate_scores(list(computers.keys()))

    

    def get_all_computers(self) -> List[VulnerableComputer]:
        logger.debug("Getting all computers")
        return VulnerableComputer.objects

    def row_to_json(self, row):
        """ Given a row, will return the json object of that row.

        Args:
            row (DB Row):
        """
        # Getting the BSON version of the row
        row = row.to_mongo()

        # Setting the date time to be readable
        DEFAULT_JSON_OPTIONS.datetime_representation = 2

        return dumps(row)

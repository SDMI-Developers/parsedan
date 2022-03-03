import datetime
import logging
import time
from typing import List
from parsedan.db.mongomodels import CVE, ParsedFile, VulnerableComputer
from pymongo.results import BulkWriteResult
import mongoengine
from pymongo import UpdateOne


logger = logging.getLogger(__name__)

class DBHandler:
    """ Handles anything that happens to the database.
    Makes it super easy to go from one db engine to the next for testing purposes (mongo/sqlalchemy)
    """

    def __init__(self, db_connection_string: str = None) -> None:
        if db_connection_string:
            self.db_connection_string = db_connection_string
            self._connect_to_db()
        else:
            # TODO: In-Memory/SQLITE parse here
            logger.error("IN_MEMORY_NOT_IMPLEMENTED!")

    def _connect_to_db(self):
        logger.info(f"connecting to db with string {self.db_connection_string}")
        mongoengine.connect(host=self.db_connection_string)

    def save_parsed_file(file_md5: str, json_file_loc: str):
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

    def file_already_parsed(file_md5: str) -> bool:
        """
        Determines whether a file was already parsed in the DB by checking the MD5 value against existing DB entries.

        Args:
            file_md5 (str): The MD5 value of the json file.
        Returns:
            bool: Whether the file is already parsed are not
        """
        logger.info(f"Checking if file already parsed. {file_md5}")
        file = ParsedFile.objects(file_md5=file_md5)

        if len(file) > 0:
            logger.info("Already parsed!")
            return True
        return False

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

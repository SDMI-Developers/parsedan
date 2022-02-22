import csv
import hashlib
import sys
import time
from datetime import datetime, date, timedelta, timezone
import json
from gzip import decompress
from json import JSONDecodeError
from typing import List
from mongoengine.errors import DoesNotExist
from netaddr import IPNetwork
from dateutil import parser
from pymongo import UpdateOne
from pymongo.results import BulkWriteResult
from requests import get
import logging
from parsedan.db.mongomodels import *
from bson.json_util import loads, dumps, DEFAULT_JSON_OPTIONS
# importing enum for enumerations
import enum

# creating enumerations using class


class FileType(enum.Enum):
    both = 0
    json = 1
    csv = 2

    @staticmethod
    def str_to_enum(filetype: str):
        filetype = filetype.lower()
        if filetype == "json":
            return FileType.json
        if filetype == "csv":
            return FileType.csv
        return FileType.both


logger = logging.getLogger(__name__)


class Utility:

    @staticmethod
    def get_gzipped_json(url: str):
        """Given a URL that contains gzipped content, will return decompressed JSON.

        Args:
            url (str): Url of Gzippeded file

        Returns:
            None | Json: Returns None on error.
        """
        try:
            return json.loads(decompress(get(url).content))
        except JSONDecodeError as e:
            logger.exception(f"Trouble decoding JSON {e}")
            return None
        except Exception as e:
            logger.exception(f"Trouble connecting to nist.... {e}")
            return None

    @staticmethod
    def calc_json_md5(file_loc: str) -> str:
        """
        Loops through a JSON file line by line and calculates the md5 value
        :param fileloc: Location of the json file.
        :return: The MD5 value of the json file.
        """
        logger.debug("Clcing file md5, Opening json file")

        try:
            # Open,close, read file and calculate MD5 on its contents
            with open(file_loc) as file_to_check:
                logger.debug("Reading JSON file")
                # read contents of the file
                data = file_to_check.read()

                # pipe contents of the file through
                md5_returned = hashlib.md5(data.encode("utf-8")).hexdigest()
                logger.info(f"file MD5: {md5_returned}")
            return md5_returned
        except Exception as e:
            logger.exception(e)
            sys.exit()

    @staticmethod
    def get_ip_ranges(fileName: str) -> list:
        """
        Utility function to read the whitelist file and convert whitelist range to min and max of an ip range

        :param fileName: Whitelist filename
        :return: Returned list in format [[minDecimal,maxDecimal,rangeString]]
        """
        ipRanges = []
        sys.stdout.write(f"\rReading whitelist file: {fileName}")
        try:
            with open(fileName, "r") as f:
                for line in f:
                    ip_network = IPNetwork(line)
                    ipRanges.append(
                        [ip_network.first, ip_network.last, line.strip()])
            return ipRanges
        except FileNotFoundError:
            msg = "Whitelist file not found! Exitting!"
            logger.exception(msg)
            print(msg)
            sys.exit()

    @staticmethod
    def parse_file(file_loc: str):
        pass


class ShodanParser:

    computers: dict = {}

    def _clear_db(self):
        """
        Call this function you want to clear the database but don't want to delete any of the downloaded
        CVE data
        """
        VulnerableComputer.drop_collection()
        return

    def checkCVEModified(self):
        """
        This function should be scheduled to run every day.
        It will download nists latest modified file and
        update the table accordingly. The file is a backlog of
        changes for the past 8 days. If this function hasn't been
        called in a 8 day period, the entire table will need
        to be checked against all of nists data.

        This function will auto check the database to confirm
        it hasn't been more then 8 days since it has run

        You can read more on how nist operates this service here:
        https://nvd.nist.gov/vuln/data-feeds#keepUpdated
        """

        # self.recreateCVETable(_modify=False)

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
                print("No CVE data exists. Downloading from nist!")
            else:
                print("Its been more then 8 days, Recreating nist table.")
            print("This may take a few minutes!")
            # Recreate table with json dump
            self.recreateCVETable(_modify=False)
        else:
            print("Downloading modified fields from nist.gov")
            # Only add new and update modified fields to db.
            url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
            self.save_cvss_to_db(url)
        print("\rCVE Up-To-Date")

    def recreateCVETable(self, _modify: bool = None):
        """
        Will download one by one all files from nist.gov and
        save them into the db.
        """
        if not _modify:
            sys.stdout.write("\rDropping old CVE collection.")
            # Delete every item from table
            CVE.drop_collection()

        # Build url from year 2002 (nist records start at 2002) to today
        for year in range(2002, date.today().year + 1):
            url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
            sys.stdout.write(f"\rDownloading CVE-{year} from nist feeds.")
            self.save_cvss_to_db(url)

    def save_cvss_to_db(self, nvdNistGzJsonURL: str):
        """

        :param nvdNistGzJsonURL:
        :param modify: If true, will check every inserted object for existence and update
        it if it does exist.
        :return: None if json failed to parse
        """
        JSON = Utility.get_gzipped_json(nvdNistGzJsonURL)
        if JSON is None:
            return

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
        sys.stdout.write("\rInserting")
        result: BulkWriteResult = CVE._get_collection().bulk_write(operations)
        # print(x.inserted_count, x.modified_count, x.upserted_count)

    def whitelist_file_to_db(self, whitelistFileName: str, onlyInsert: bool = None):
        """
        Add entries from a newline delimited file of ipranges to the db.
        :param whitelistFileName: File location to get list of ranges
        :param onlyInsert: Set to true when you just want to add more ips to whitelist. Won't drop
        the entire table before adding the provided whitelist file
        """
        # Read the whitelist file
        ipRanges = Utility.get_ip_ranges(whitelistFileName)

        if not onlyInsert:
            sys.stdout.write(f"\rDropping all rows in whitelist!")
            # Drop all entries
            WhitelistRange.drop_collection()

        sys.stdout.write(f"\rSaving whitelist to DB")
        for ipRange in ipRanges:
            whitelist = WhitelistRange()
            whitelist.minDecimal = ipRange[0]
            whitelist.maxDecimal = ipRange[1]
            whitelist.rangeString = ipRange[2]
            whitelist.save()

        # Since whitelist changed, make sure to update every row with this change
        self.assign_whitelisted_ips(reset_whitelisted=True)

        print(f"\rWhitelist successfully updated!")

    def assign_whitelisted_ips(self, reset_whitelisted: bool = False):
        """
        Loops through db and determines if an ip is whitelisted.

        :param reset_whitelisted: If true will turn all computers to whitelisted false before checking for more
        whitelisted. Useful for when the whitelist file changes and may remove computers that were previously in it.
        """

        if reset_whitelisted:
            sys.stdout.write("\rResetting all whitelisted computers to false.")
            # Reset the value of all whitelisted computers.
            curr_whitelisted_comps = VulnerableComputer.objects(
                is_whitelisted=True)
            for important_comp in curr_whitelisted_comps:
                important_comp.is_whitelisted = False
                important_comp.save()

        sys.stdout.write("\rMatching vulnerable computers with whitelist")

        # Loop through ip range and check to see if it exists in the db
        for ip_range in WhitelistRange.objects():
            matched_vulnerable_computers = VulnerableComputer \
                .objects(ip__gte=ip_range.minDecimal, ip__lte=ip_range.maxDecimal)
            for computer in matched_vulnerable_computers:
                computer.is_whitelisted = True
                computer.save()

    def parse_mongo_json_line(self, data, existing_comp=None):
        """
        TODO: DOCUMENT THIS BETTER
        :param data:
        :param existing_comp:
        :return:
        """
        c_date = datetime.datetime \
            .strptime(data["timestamp"].split("T")[0], "%Y-%m-%d").date()
        current_date = str(c_date)

        # Use the existing db object and date objects if it already exists
        if existing_comp:
            vuln_computer: VulnerableComputer = existing_comp["computer"]
            ports = existing_comp["ports"]
            cves = existing_comp["cves"]

            datetime_object = datetime.datetime.strptime(
                vuln_computer.date_added, '%Y-%m-%d').date()
            # Use the older date for date added
            if c_date < datetime_object:
                vuln_computer.date_added = current_date
        else:
            # New vuln computer that is a db model
            vuln_computer = VulnerableComputer()
            vuln_computer.date_added = current_date
            ports = {}
            cves = []

        if "asn" in data:
            vuln_computer.asn = data["asn"]
        vuln_computer.ip = data["ip"]
        vuln_computer.ip_str = data["ip_str"]

        # Check if the comp is whitelisted
        vuln_computer.is_whitelisted = False  # self.isImportantIP(data["ip"])

        # Location information
        if "location" in data:
            vuln_computer.city = data["location"]["city"]
            vuln_computer.state = data["location"]["region_code"]
            vuln_computer.lat = data["location"]["latitude"]
            vuln_computer.lng = data["location"]["longitude"]

        # Details
        if "os" in data:
            vuln_computer.os = data["os"]
        if "isp" in data:
            vuln_computer.isp = data["isp"]
        if 'org' in data:
            vuln_computer.org = data["org"]

        # These will be calculated later
        vuln_computer.high_score = 0.0
        vuln_computer.current_score = 0.0

        db_port = PortHistory()
        db_port.port = data["port"]
        db_port.date_observed = current_date
        db_port.description = [data["data"]]

        if data["transport"].lower() == "udp":
            db_port.udp = True
        if data["transport"].lower() == "tcp":
            db_port.tcp = True

        # Getting the ports object setup
        if db_port.date_observed not in ports:
            ports[db_port.date_observed] = {}
        if db_port.port not in ports[db_port.date_observed]:
            ports[db_port.date_observed][db_port.port] = db_port
        else:
            ports[db_port.date_observed][db_port.port].description.append(
                data["data"])

        if "vulns" in data:
            # Add vulns to date observed table
            vulnKeys = list(data["vulns"].keys())
            for vuln in vulnKeys:
                if "ms" not in vuln.lower():
                    if vuln.startswith("~"):
                        vuln = vuln[1:]
                    db_cve = CVEHistory()
                    db_cve.cveName = vuln
                    db_cve.date_observed = current_date
                    cves.append(db_cve)

        return {"computer": vuln_computer, "ports": ports, "cves": cves}

    def is_file_aready_parsed(self, file_md5) -> bool:
        """
        Determines whether a file was already parsed in the DB by checking the MD5 value against existing DB entries.

        Args:
            file_md5 (str): The MD5 value of the json file.
        Returns:
            bool: Whether the file is already parsed are not
        """

        file = ParsedFile.objects(file_md5=file_md5)
        if len(file) > 0:
            print(f"Already parsed, skipping!")
            return True
        return False

    def add_lines(lines: List[str]):
        pass

    def save_to_db(self):
        self.save_cleaned_data(self.computers)

    def add_line(self, line: str):
        try:
            logger.debug(f"Adding line: {line}")
            line_data = json.loads(line)
            ip = line_data["ip"]

            if ip not in self.computers:
                self.computers[ip] = {}
                self.computers[ip] = self.parse_mongo_json_line(line_data)
            else:
                self.computers[ip] = self.parse_mongo_json_line(
                    line_data, self.computers[ip])
        except KeyError as e:
            logging.warn(f"Error reading key {e}")
        except ValueError:
            logging.warn(f"JSON error for that line! {e}")

    def output_to_json(self, output_file_loc: str, current_state: bool = True):
        """ Outputs to a json file

        Args:
            output_file_loc (str): The location and filename of the output file.
            current_state (bool): Whether to output the current object state, or all objects from the DB
        """
        logger.info(
            f"Outputting file to json with file location: {output_file_loc}")
        if current_state:
            with open(output_file_loc, "w") as out_file:
                for key in self.computers:
                    computer = self.computers[key]
                    print(computer["computer"])

    def parse_json_file(self, json_file_loc: str):
        """

        :param json_file_loc: File name/location of json file to parse
        :return:
        """
        # Getting the MD5 of the json file
        file_md5 = Utility.calc_json_md5(json_file_loc)

        # Check if file was already parsed.
        if self.is_file_aready_parsed(file_md5=file_md5):
            return

        # Used to calculate how much time we spent parsing
        start = time.time()

        with open(json_file_loc, "r") as file:
            cleaned_data = {}
            i = 0
            for line in file:
                sys.stdout.write("\rRow count:" + str(i))
                i += 1

                try:
                    line_data = json.loads(line)
                    ip = line_data["ip"]
                    # TODO: Check for ignored ASN's

                    if ip not in cleaned_data:
                        cleaned_data[ip] = {}
                        cleaned_data[ip] = self.parse_mongo_json_line(
                            line_data)
                    else:
                        cleaned_data[ip] = self.parse_mongo_json_line(
                            line_data, cleaned_data[ip])

                except KeyError as e:
                    print("Error reading key", e)
                except ValueError:
                    print("JSON Error!")

            # flatten ports
            for ip in cleaned_data:
                ports = []
                for date in cleaned_data[ip]["ports"]:
                    for port in cleaned_data[ip]["ports"][date]:
                        ports.append(cleaned_data[ip]["ports"][date][port])
                cleaned_data[ip]["ports"] = ports

            print("\rDone Cleaning Data ", time.time() - start)
            # Save the data to the db
            self.save_cleaned_data(cleaned_data)

            #whitelist_time = time.time()
            # self.assign_whitelisted_ips()
            #print(f"\rDone updating Important Computers. Time: {time.time() - whitelist_time}")

            print("SCORE CALCULATION DISABLED")
            # self.calculate_scores(list(cleaned_data.keys()))

            # Saving the md5 of the parsed file to the DB so we dont do it again.
            parsed_file = ParsedFile()
            parsed_file.file_md5 = file_md5
            parsed_file.filename = json_file_loc
            parsed_file.datetime_parsed = datetime.datetime.now()
            parsed_file.save()
            print(f"\rFinished File! Total Time: {time.time() - start}")

    def save_cleaned_data(self, cleaned_data: dict, calculate_scores: bool = True):
        """
        Saves the cleaned data to the database.
        :param cleaned_data:
        :param calculate_scores:
        :return:
        """
        logger.info("Saving data!")

        logger.debug("Building the DB query for insertion.")
        operations = []

        insert_data_time = time.time()

        if len(list(cleaned_data.keys())) == 0:
            logger.debug("Empty data given!")
            return

        for ip in cleaned_data:
            computer = cleaned_data[ip]["computer"]._data

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
            ports = []
            for date in cleaned_data[ip]["ports"]:
                for port in cleaned_data[ip]["ports"][date]:
                    ports.append(cleaned_data[ip]["ports"][date][port])

            # # Insert/Update port history
            for port in ports:
                operations.append(UpdateOne({"_id": ip},
                                            {"$addToSet": {"port_history": port._data}}, upsert=True))
            for cve in cleaned_data[ip]["cves"]:
                operations.append(UpdateOne({"_id": ip},
                                            {"$addToSet": {"cve_history": cve._data}}, upsert=True))

        logger.debug("Saving computers to database")
        result: BulkWriteResult = VulnerableComputer._get_collection().bulk_write(operations)

        logger.info(
            f"Done saving data! Time: {time.time() - insert_data_time} Added {result.upserted_count}, Updated {result.modified_count}")

        if calculate_scores:
            self.calculate_scores(list(self.computers.keys()))
        self.computers = {}

    # Used by calcaulte score and calculate scores functions
    _cvss_cache = {}

    def calculate_score(self, computer: VulnerableComputer, timestamp: date = None) -> float:

        # Sort dates
        computer.port_history = sorted(
            computer.port_history, key=lambda x: x.date_observed, reverse=True)

        # Getting the most current date of port history
        most_current_date = computer.port_history[0].date_observed
        most_current_date = datetime.datetime.strptime(
            most_current_date, "%Y-%m-%d")

        range_date = most_current_date - timedelta(days=5)
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
            if cve_name not in self._cvss_cache:
                try:
                    self._cvss_cache[cve_name] = CVE.objects.get(pk=cve_name)
                except DoesNotExist:
                    continue

            cve: CVE = self._cvss_cache[cve_name]
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

    def calculate_scores(self, ip_list: List, recalculateAll: bool = None):
        """
        :param ip_list: List of IP addresses that have changed so they need there score recalculated.
        :param recalculateAll: If this is specified, will recalculate scores for every computer
        and every date in the db. This could take a while, but should be specified when the
        scoring algorithm has changed.
        """
        if recalculateAll:
            logger.warn("RECALCULATE ALL NOT IMPLEMENTED!")

        if len(ip_list) == 0:
            logger.debug("Ip list empty")
            return

        # Amount to calculate scores for at a time
        LIMIT_AMT = 10000

        logger.info("Calculating scores")
        start = time.time()
        i = 0

        tot = 0
        operations = []
        while i <= len(ip_list):
            cmps: List[VulnerableComputer] = VulnerableComputer.objects(
                pk__in=ip_list).skip(i).limit(LIMIT_AMT)
            for comp in cmps:
                score = self.calculate_score(comp)
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
        # Clear cached cvss scores
        self._cvss_cache = {}
        # Writing changes to db
        logger.debug(f"Saving scores to db")

        VulnerableComputer._get_collection().bulk_write(operations)
        logger.info(f"Done calculating scores! Time: {time.time() - start}")

    def output_computer_summary(self, file_loc: str, file_type: FileType = FileType.json):
        logger.info(f"Outputting summary {file_loc} {file_type}")

        logger.debug("Getting computers")
        vuln_computers = VulnerableComputer.objects

        if file_type == FileType.json or file_type == FileType.both:
            self.output_json(filename=file_loc,
                             vulnerable_computers=vuln_computers)
        if file_type == FileType.csv or file_type == FileType.both:
            self.output_csv(filename=file_loc,
                            vulnerable_computers=vuln_computers)

    def load_cve_json(self):
        # Loading or Opening the json file
        with open('cve_data.json') as file:
            file_data = json.load(file)
        for row in file_data:
            row["lastModifiedDate"] = datetime.datetime.fromtimestamp(float(row["lastModifiedDate"]["$date"]) / 1000,
                                                                      timezone.utc)
            row["publishedDate"] = datetime.datetime.fromtimestamp(float(row["publishedDate"]["$date"]) / 1000,
                                                                   timezone.utc)

        cve_table = CVE._get_collection()
        cve_table.insert_many(file_data)

    def output_csv(self, vulnerable_computers:List[VulnerableComputer], filename: str):
        """ Outputs the given vulnerable computers objects to csv

        Args:
            filename (str): The name/ location of file to output
            vulnerable_computers (List[VulnerableComputer]): A list of vulnerable computers from mongoengine
        """

        if not filename.endswith('.csv'):
            logger.debug("Filename didnt contain .csv")
            filename += ".csv"

        logger.info(f"Outputting to csv File: {filename}")
        if len(vulnerable_computers) == 0:
            logger.info("No objs to output to csv file.")
            return

        logger.info(f"Outputting to csv File: {filename}")

        logger.debug("Building headers.")
        headers = vulnerable_computers[0].to_mongo().to_dict()

        # Renaming ip ip_str to ip for the headers
        headers["ip"] = headers.pop("ip_str")

        headers.pop("port_history", None)
        headers.pop("cve_history", None)

        headers.pop("_id", None)

        headers = list(headers.keys())

        cve_dates = set()
        port_dates = set()

        logger.debug("Getting dates for headers")
        for o in vulnerable_computers:
            for cve in o.cve_history:
                cve_dates.add("Open CVE's on {}".format(cve.date_observed))
            for port in o.port_history:
                port_dates.add("Open Port's on {}".format(port.date_observed))

        logger.debug("Sorting CVS dates and ports")
        cve_dates = sorted(cve_dates)
        port_dates = sorted(port_dates)

        headers += port_dates
        headers += cve_dates

        logger.debug(f"CSV headers built {headers}")

        logger.info("Opening csv file to write to!")
        with open(filename, 'w', newline="") as csvfile:
            writer = csv.DictWriter(
                csvfile, fieldnames=headers, extrasaction='ignore')
            writer.writeheader()
            for o in vulnerable_computers:
                csv_row = o.to_mongo().to_dict()
                csv_row["ip"] = csv_row.pop("ip_str")

                # Build port dates into object
                for date in port_dates:
                    csv_row[date] = ""
                for date in cve_dates:
                    csv_row[date] = ""

                for port in o.port_history:
                    csv_row[f"Open Port's on {port.date_observed}"] += f"{port.port} "
                for cve in o.cve_history:
                    csv_row[f"Open CVE's on {cve.date_observed}"] += f"{cve.cveName} "

                logging.debug(f"Writing row to file: {filename} {csv_row}")
                writer.writerow(csv_row)

    def output_json(self, filename: str, vulnerable_computers:List[VulnerableComputer]):
        """ Outputs the given vulnerable computers objects to json

        Args:
            filename (str): The name/ location of file to output
            vulnerable_computers (List[VulnerableComputer]): A list of vulnerable computers from mongoengine
        """
        if not filename.endswith('.json'):
            logger.debug("Filename didnt contain .json")
            filename += ".json"

        logger.info(f"Writing {filename} to json file")
        with open(filename, "w") as fp:
            for computer in vulnerable_computers:
                # Getting the BSON version of the row
                row = computer.to_mongo()
                # Setting the date time to be readable
                DEFAULT_JSON_OPTIONS.datetime_representation = 2

                logging.debug(f"Writing row to file: {filename} {row}")
                fp.write(dumps(row) + "\n")

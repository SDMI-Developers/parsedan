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
from requests import get
import logging
from parsedan.Utility import Utility
from parsedan.db.DBHandler import DBHandler
from parsedan.db.mongomodels import *
from bson.json_util import loads, dumps, DEFAULT_JSON_OPTIONS
import enum
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

class ShodanParser:

    computers: dict = {}
    def __init__(self, connection_string: str = None) -> None:
        self.db_Handler = DBHandler(db_connection_string=connection_string)

    def _clear_db(self):
        """
        Call this function you want to clear the database but don't want to delete any of the downloaded
        CVE data
        """
        VulnerableComputer.drop_collection()
        return

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
                logger.debug("Its been more then 8 days, Recreating nist table.")

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
        for year in range(2002, date.today().year + 1):
            url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
            logger.info(f"Downloading CVE-{year} from nist feeds.")
            
            if self.save_nist_cve_to_db(url) is None:
                logger.debug("NO CVE data saved")
    

    def save_nist_cve_to_db(self, nvdNistGzJsonURL: str):
        """

        :param nvdNistGzJsonURL: URL of gzipped nist file.
        :return: None if json failed to parse, else return results of mongoengine insert
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

    def save_to_db(self):
        self._save_cleaned_data()

    def add_line(self, line: str):
        try:
            logger.debug(f"Adding line: {line}")
            line_data = json.loads(line)
            ip = float(line_data["ip"])
            # check if computer exists already
            if ip not in self.computers:
                logger.debug("Computer doesn't exist in memory dict, adding.")
                self.computers[ip] = {}
                self.computers[ip] = self.parse_mongo_json_line(line_data)
            else:
                logger.debug("Computer already exists in memory dict")
                self.computers[ip] = self.parse_mongo_json_line(
                    line_data, self.computers[ip])
        except KeyError as e:
            logger.debug(f"Error reading key {e}")
        except ValueError as e:
            logger.debug(f"JSON error for that line! {e}")

    def parse_json_file(self, json_file_loc: str):
        """
        Given the location of a json file, will parse it and add it to the database. 
        :param json_file_loc: File name/location of json file to parse
        :return:
        """
        # Getting the MD5 of the json file
        file_md5 = Utility.calc_json_md5(json_file_loc)

        # Check if file was already parsed.
        if self.db_Handler.file_already_parsed(file_md5=file_md5):
            return

        # Used to calculate how much time we spent parsing
        start = time.time()

        with open(json_file_loc, "r") as file:
            for line in file:
                self.add_line(line)

            #whitelist_time = time.time()
            # self.assign_whitelisted_ips()
            #print(f"\rDone updating Important Computers. Time: {time.time() - whitelist_time}")

            # Save the data to the db
            self._save_cleaned_data()

            # Saving the md5 of the parsed file to the DB so we dont do it again.
            self.db_Handler.save_parsed_file(file_md5=file_md5, json_file_loc=json_file_loc)

            print(f"\rFinished File! Total Time: {time.time() - start}")

    def _save_cleaned_data(self):
        self.db_Handler.save_computers(computers=self.computers)

        # Clear current computers in memory since they are now stored in DB
        logger.debug("Clearing computers dict...")
        self.computers = {}

    def output_computer_summary(self, file_loc: str, file_type: FileType = FileType.json):
        logger.info(f"Outputting summary {file_loc} {file_type}")

        logger.debug("Getting computers")
        vuln_computers = VulnerableComputer.objects

        if file_type == FileType.json or file_type == FileType.both:
            self._output_json(filename=file_loc,
                              vulnerable_computers=vuln_computers)
        if file_type == FileType.csv or file_type == FileType.both:
            self._output_csv(filename=file_loc,
                             vulnerable_computers=vuln_computers)

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
            logger.exception("Unabled to save CVE file, will have to manually be redownloaded.")
            

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
                                                                        timezone.utc)
                    line["publishedDate"] = datetime.datetime.fromtimestamp(float(line["publishedDate"]["$date"]) / 1000,
                                                                    timezone.utc)
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

    def _output_csv(self, vulnerable_computers: List[VulnerableComputer], filename: str):
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

    def _output_json(self, filename: str, vulnerable_computers: List[VulnerableComputer]):
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

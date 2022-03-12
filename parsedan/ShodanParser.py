import csv
import datetime
import sys
import time
import json
from typing import List
import logging
from parsedan.Utility import Utility
import enum
from parsedan.db.SQLDBHandler import DBHandler
from parsedan.db.sqlmodels import Computer, CVE, CVEHistory, PortHistory


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
    port_history: dict = {}
    cve_history: dict = {}

    def __init__(self, connection_string: str = None) -> None:
        self.db_Handler = DBHandler(db_connection_string=connection_string)

    def save_to_db(self):
        self._save_computers()

    def add_line(self, line: dict):
        try:
            ip = float(line["ip"])
            c_date = datetime.datetime.strptime(
                line["timestamp"].split("T")[0], "%Y-%m-%d").date()

            if ip in self.computers.keys():
                computer = self.computers[ip]
                if c_date < computer["date_added"]:
                    computer["date_added"] = c_date

            else:
                computer = {}
                computer["ip"] = line["ip"]
                computer["ip_str"] = line["ip_str"]
                computer["date_added"] = c_date
                # Location information
                if "location" in line:
                    computer["city"] = line["location"]["city"]
                    computer["state"] = line["location"]["region_code"]
                    computer["lat"] = line["location"]["latitude"]
                    computer["lng"] = line["location"]["longitude"]
                # Details
                if "os" in line:
                    computer["os"] = line["os"]
                if "isp" in line:
                    computer["isp"] = line["isp"]
                if 'org' in line:
                    computer["org"] = line["org"]
                port = {}
                port["computer_id"] = computer["ip"]
                port["port"] = line["port"]
                port["date_observed"] = c_date
                t = (line["port"], c_date, computer["ip"])
                self.port_history[t] = port
                if "vulns" in line:
                    # Add vulns to date observed table
                    vuln_keys = list(line["vulns"].keys())
                    for vuln in vuln_keys:
                        if "ms" not in vuln.lower():
                            if vuln.startswith("~"):
                                vuln = vuln[1:]
                            cve = {}
                            cve["computer_id"] = computer["ip"]
                            cve["date_observed"] = c_date
                            cve["cve_name"] = vuln
                            t = (
                                cve["cve_name"], cve["date_observed"], cve["computer_id"])
                            self.cve_history[t] = cve
                self.computers[computer["ip"]] = computer
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
        if self.db_Handler.is_file_parsed(file_md5=file_md5):
            return

        logger.info(f"Parsing json file {json_file_loc}")

        # Used to calculate how much time we spent parsing
        start = time.time()

        with open(json_file_loc, "r") as file:
            for line in file:
                line = json.loads(line)
                self.add_line(line)

            # Save the data to the db
            self._save_computers()

            # Saving the md5 of the parsed file to the DB so we dont do it again.
            self.db_Handler.save_parsed_file(
                file_md5=file_md5, json_file_loc=json_file_loc)

            print(f"\rFinished File! Total Time: {time.time() - start}")

    def _save_computers(self):

        self.db_Handler.upsert_objects(Computer, list(self.computers.values()))
        self.db_Handler.upsert_objects(
            PortHistory, list(self.port_history.values()))
        self.db_Handler.upsert_objects(
            CVEHistory, list(self.cve_history.values()))

        logger.debug("Committing to DB")
        self.db_Handler.session.commit()
        # Clear current computers in memory since they are now stored in DB
        logger.debug("Clearing computers dict...")
        self.computers = {}
        self.port_history = {}
        self.cve_history = {}

    def output_computer_summary(self, file_loc: str, file_type: FileType = FileType.json):
        logger.info(f"Outputting summary {file_loc} {file_type}")

        computer_count = self.db_Handler.session.query(Computer).count()
        ROW_LIMIT = 30000

        # Make sure row limit is never greater then count
        ROW_LIMIT = computer_count if computer_count >= ROW_LIMIT else ROW_LIMIT

        csv_headers = self._build_csv_headers()

        # Write to the file a few at a time (in case we have a large database)
        for i in range(0, computer_count, ROW_LIMIT):
            vuln_computers = self.db_Handler.get_computers(i, ROW_LIMIT)

            if file_type == FileType.json or file_type == FileType.both:
                self._output_json(filename=file_loc,
                                  vulnerable_computers=vuln_computers)
            if file_type == FileType.csv or file_type == FileType.both:
                self._output_csv(filename=file_loc,
                                 computers=vuln_computers,
                                 csv_headers=csv_headers)

    def _build_csv_headers(self) -> List:
        """ Builds CSV headers for our output
        These need to be the same for every output since its a csv

        Returns:
            List: List of CVE headers
        """
        logger.debug("Building headers.")
        headers = [column.key for column in Computer.__table__.columns]

        logger.debug("Getting dates for headers")
        dates = self.db_Handler.get_dates()

        cve_dates = sorted(dates[0])
        port_dates = sorted(dates[1])

        cve_dates = [f"Open CVE's on {r}" for r in cve_dates]
        port_dates = [f"Open Port's on {r}" for r in port_dates]

        headers += port_dates
        headers += cve_dates

        logger.debug(f"CSV headers built {headers}")

        return headers

    def _output_csv(self, computers: List[Computer], filename: str, csv_headers: list):
        """ Outputs the given vulnerable computers objects to csv

        Args:
            filename (str): The name/ location of file to output
            vulnerable_computers (List[VulnerableComputer]): A list of vulnerable computers from mongoengine
        """

        if not filename.endswith('.csv'):
            logger.debug("Filename didnt contain .csv")
            filename += ".csv"

        if len(computers) == 0:
            logger.info("No objs to output to csv file.")
            return

        logger.info(f"Outputting to csv File: {filename}")

        logger.info("Opening csv file to write to!")
        with open(filename, 'w', newline="") as csvfile:
            writer = csv.DictWriter(
                csvfile, fieldnames=csv_headers, extrasaction='ignore')

            writer.writeheader()

            for o in computers:
                try:
                    csv_row = {}

                    # Build port dates into object
                    for header in csv_headers:
                        csv_row[header] = ""

                    # Adding ports/cve to rows
                    for port in o.port_history:
                        csv_row[f"Open Port's on {port.date_observed}"] += f"{port.port} "
                    for cve in o.cve_history:
                        csv_row[f"Open CVE's on {cve.date_observed}"] += f"{cve.cve_name} "

                    comp_dict = o.__dict__
                    # Removing unecessary keys
                    comp_dict.pop("_sa_instance_state")
                    comp_dict.pop("cve_history")
                    comp_dict.pop("port_history")

                    # Adding the computer to the row dict
                    for c in comp_dict:
                        csv_row[c] = comp_dict[c]

                    logger.debug(f"Writing row to file: {filename} {csv_row}")
                    writer.writerow(csv_row)
                except Exception as e:
                    logger.debug(
                        f"Error parsing that computer to CSV: {o} {e}")

        return

    def _output_json(self, filename: str, vulnerable_computers: List[Computer]):
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
            try:
                for computer in vulnerable_computers:
                    row = json.dumps(computer.as_dict(), default=str)

                    logger.debug(f"Writing row to file: {filename} {row}")

                    fp.write(row + "\n")
            except Exception as e:
                logger.exception(f"Error saving JSON file {e}")
                print(f"Error saving JSON file! {e}")

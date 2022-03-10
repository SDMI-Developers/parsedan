
import datetime
import json
import sys
import time
from typing import List
from sqlalchemy import inspect
import sqlalchemy
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.sql.expression import Tuple
from pymongo_inmemory import MongoClient
import parsedan
from parsedan.Utility import Utility
from parsedan.db.SQLDBHandler import DBHandler
from parsedan.db.sqlmodels import Computer, PortHistory, CVEHistory
import glob

dbhandler = DBHandler(
    "postgresql+psycopg2://shodan_da:shodan@130.39.245.205:5432/shodan")

# dbhandler = DBHandler("sqlite:///db1.db")

# dbhandler.load_cve_json("/home/jdolbe1/.parsedan/cve_data.json")


def parse(file):
    # la-2021-10-04.json la-2021-08-18.json la-2021-10-24.json
    with open(file, "r") as file:
        computers = {}
        port_history = {}
        cve_history = {}

        i = 0
        start = time.time()

        for line in file:
            print(f"{i}", end="\r")
            i += 1
            line = json.loads(line)
            try:
                ip = float(line["ip"])
                c_date = datetime.datetime.strptime(
                    line["timestamp"].split("T")[0], "%Y-%m-%d").date()

                if ip in computers.keys():
                    computer = computers[ip]
                    if c_date < computer["date_added"]:
                        computer.date_added = c_date
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

                    port_history[t] = port

                    if "vulns" in line:
                        # Add vulns to date observed table
                        vulnKeys = list(line["vulns"].keys())
                        for vuln in vulnKeys:
                            if "ms" not in vuln.lower():
                                if vuln.startswith("~"):
                                    vuln = vuln[1:]
                                cve = {}
                                cve["computer_id"] = computer["ip"]
                                cve["date_observed"] = c_date
                                cve["cve_name"] = vuln
                                t = (
                                    cve["cve_name"], cve["date_observed"], cve["computer_id"])
                                cve_history[t] = cve

                computers[computer["ip"]] = computer
            except Exception:
                continue

        print(f"Parse time: {time.time() - start}")

        dbhandler.upsert_objects(Computer, list(computers.values()))
        dbhandler.upsert_objects(PortHistory, list(port_history.values()))
        dbhandler.upsert_objects(CVEHistory, list(cve_history.values()))

        dbhandler.session.commit()

        print(f"Total time: {time.time() - start}")

        print("TOTAL: {}".format(i))


def parse_files():
    # parse("/home/jdolbe1/lsp-heuristics/data/shodan/la-2021-10-24.json")
    # All files and directories ending with .txt and that don't begin with a dot:
    json_files = glob.glob("/home/jdolbe1/lsp-heuristics/data/shodan/*.json")
    json_files = sorted(json_files)
    for file in json_files:
        print("Parsing", file)
        parse(file)


def calculate_scores():
    dbhandler._calculate_scores()


calculate_scores()

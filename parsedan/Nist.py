import datetime
import logging
from typing import List

from sqlalchemy import null
import parsedan
from parsedan.Utility import Utility
from parsedan.db.sqlmodels import CVE


logger = logging.getLogger(__name__)


class Nist:
    """Responsible for collecting and maintaining NIST data
    """

    def __init__(self, dbhandler) -> None:
        self.session = dbhandler.session
        self.dbhandler = dbhandler

    def check_cve_modified(self):
        logger.info("Checking if CVE has been updated in the last 8 days.")

        # Checking if its been more then eight days since a cve was modified.
        # If so we need to rebuild our cve table
        last_modified: CVE = self.session.query(CVE).order_by(
            CVE.last_modified_date.desc()).first()

        rebuild_cve_db = True
        if last_modified:
            days = (datetime.datetime.today().date() -
                    last_modified.last_modified_date).days

            if days < 8:
                logger.info("Nist data younger then 8 days")
                rebuild_cve_db = False
            else:
                logger.info("Nist data older then 8 days")

        if rebuild_cve_db:
            logger.debug(
                "Its been more then 8 days or no nist data exists")

            print("Downloading data from NIST.\nThis may take a few minutes!")

            # Recreate table
            self.create_cve_table()
        else:
            self._download_modified()

        logger.info("Finished CVE checks... Up to date!")

    def _drop_nist_data(self):
        logger.info("Dropping nist table rows")
        self.session.query(CVE).delete()
        self.session.commit()

    def create_cve_table(self):
        logger.info("Creating nist cve table!")
        self._drop_nist_data()

        for year in range(2002, datetime.date.today().year + 1):
            url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
            logger.info(f"Downloading CVE-{year} from nist feeds.")

            cves: List[CVE] = self._parse_nist_url(url)
            self._save_cves(cves)

    def _download_modified(self):
        logger.info("Downloading modified fields from nist.gov")
        # Only add new and update modified fields to db.
        url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
        cves = self._parse_nist_url(url)
        self._save_cves(cves)
        self.session.commit()

    def _save_cves(self, cves):
        """ Saves the given cves to the database

        Args:
            cves (List[CVE]): A list of cve data
        """
        if cves is None:
            logger.debug("No CVE data to save")
            return

        logger.debug("Saving CVES")

        cves_list_dict = []
        # Create a list of sqlalchemy objects
        for x in cves:
            d = x.__dict__
            # Remove the instance state from dictionary
            d.pop("_sa_instance_state")
            cves_list_dict.append(d)

        # Save the cve data
        self.dbhandler.upsert_objects(CVE, cves_list_dict)
        self.session.commit()

    def _parse_nist_url(self, nist_gz_url: str) -> List[CVE]:
        """ Given nist url will download and parse the file returning an array of CVE objects

        Args:
            nist_gz_url (str): Nist URL with gzipped content

        Returns:
            (List[CVE])
        """

        JSON = Utility.get_gzipped_json(nist_gz_url)
        if JSON is None:
            return None

        logger.debug("Parsing CVE items")
        cves = []
        for cve_item in JSON["CVE_Items"]:
            cve: CVE = CVE()
            cve_name = cve_item["cve"]["CVE_data_meta"]["ID"]
            cve.cve_name = cve_name

            # Checking if CVSS 2/3 scores exists
            if "baseMetricV2" in cve_item["impact"]:
                cve.cvss_20 = cve_item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            else:
                cve.cvss_20 = None
            if "baseMetricV3" in cve_item["impact"]:
                cve.cvss_30 = cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            else:
                cve.cvss_30 = None
            cve.published_date = datetime.datetime.strptime(
                cve_item["publishedDate"], "%Y-%m-%dT%H:%MZ")

            cve.last_modified_date = datetime.datetime.strptime(
                cve_item["lastModifiedDate"], "%Y-%m-%dT%H:%MZ")

            cve_descriptions = cve_item["cve"]["description"]["description_data"]
            if len(cve_descriptions) > 0:
                cve.summary = cve_descriptions[0]["value"]

            cves.append(cve)
        return cves

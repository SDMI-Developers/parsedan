import hashlib
import sys
import json
from gzip import decompress
from json import JSONDecodeError
from netaddr import IPNetwork
from requests import get
import logging
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
            for _ in range(5):
                try:
                    content = get(url, timeout=5).content
                    logger.info(f"Done downloding {url}")
                    return json.loads(decompress(content))
                except TimeoutError:
                    logger.debug("Timeout.. retrying...")
                    pass
            raise Exception
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
        logger.debug("Calculating file md5, Opening json file")

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

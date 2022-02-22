import logging
import os
from configparser import ConfigParser
from pathlib import Path

import click

logger = logging.getLogger(__name__)

class CLIHandler:
    path: str
    config: ConfigParser

    @staticmethod
    def echo_header():
        logger.debug("Printing header")
        click.echo("-------------------------------------------\n"
                   "--------- Parsedan Shodan Parser ----------\n"
                   "---- Louisiana State University - SDMI ----\n"
                   "-------------------------------------------")

    def create_config(self):
        # Get the configparser object
        self.config.add_section("SHODAN")
        self.config.set("SHODAN",
                        "# You can obtain this API key by following: https://developer.shodan.io/api/requirements",
                        None)
        self.config.set("SHODAN", "api_key", "")
        self.save_config()

    def save_config(self):
        logger.debug("Saving config!")
        # Write the above sections to config.ini file
        with open(self.path, 'w') as conf:
            self.config.write(conf)

    def setup_config(self):
        self.config = ConfigParser(allow_no_value=True)

        if not os.path.exists(self.path):
            logger.info("Config file doesn't exist! Creating...")
            self.create_config()
        else:
            logger.info("Config file exists! Reading...")
            self.config.read(self.path)

    def __init__(self, dir):
        self.path = os.path.join(dir, "config.ini")
        self.setup_config()

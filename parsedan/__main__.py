import json
import logging
import os
import sys
import shodan
from mongoengine import connect
from pymongo_inmemory import MongoClient
import click
from pathlib import Path
from parsedan.CLI_Handler import CLIHandler

# Logging configuration
import logging
import logging.handlers

from parsedan.ShodanParser import FileType, ShodanParser

home_dir = os.path.join(str(Path.home()), ".parsedan")
Path(home_dir).mkdir(exist_ok=True)

if __name__ == "__main__":
    logging.basicConfig(filename=f"{home_dir}/output.log", level=logging.INFO,
                        format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

    logger = logging.getLogger("Parsedan." + __name__)



cli_handler = CLIHandler(dir=home_dir)


@click.group()
def cli():
    pass


@cli.command()
@click.option('--output-original', default=False)
@click.option('--output-partial-summary/--no-output-partial-summary', help="Output the summary to json/csv file every 1000 results. May slow down the operation once file starts to get big. DEFAULT: False", default=False)
@click.option('--limit', help='The number of results you want to download. -1 to download all the data possible.', default=-1, type=int)
@click.option('--filetype', help='Type of file to create, options are "csv", "json", or "both". Default "csv"', default=FileType.csv, type=FileType)
@click.argument('filename', metavar='<filename>')
@click.argument('query', metavar='<search query>', nargs=-1)
def start(output_original, output_partial_summary, limit, filetype, filename, query):
    logger.info(
        f"Called start with option values: Output Original: {output_original} Output Partial Summary: {output_partial_summary} Limit: {limit} Filetype: {filetype} Filename: {filename} Query: {query}")
    cli_handler.echo_header()

    logger.info("Reading config file for key")

    API_KEY = cli_handler.config["SHODAN"].get("api_key")

    if not API_KEY:
        logger.info("No API_Key provided!")
        click.ClickException(
            "Please provide an api key by calling `parsedan init [APIKEY]`").show()
        sys.exit(1)

    api = shodan.Shodan(API_KEY)

    # Create the query string out of the provided tuple
    query = ' '.join(query).strip()

    # Make sure the user didn't supply an empty string
    if query == '':
        logger.exception("Empty search query provided!")
        raise click.ClickException('Empty search query')

    filename = filename.strip()
    if filename == '':
        logger.exception("Empty filename")
        raise click.ClickException('Empty filename')

    # Add the appropriate extension if it's not there atm
    if not filename.endswith('.json'):
        logger.debug("Appended filename to output file")
        filename += '.json'

    logger.info("Querying API.")

    print("Querying Shodan API...", end="\r")
    try:
        total = api.count(query)['total']
        info = api.info()
        
        logger.info(f"Got total and api info: {total} {info}")
    except Exception:
        logger.exception("api info returned error!")
        raise click.ClickException(
            'The Shodan API is unresponsive at the moment, please try again later.')
    # Erase previous line
    print("                      ", end="\r")
    # Print some summary information about the download request
    click.echo('Search query:\t\t\t{}'.format(query))
    click.echo('Total number of results:\t{}'.format(total))
    click.echo('Query credits left:\t\t{}'.format(info['unlocked_left']))
    click.echo('Output file:\t\t\t{}'.format(filename))

    if limit > total:
        limit = total

    # A limit of -1 means that we should download all the data
    if limit <= 0:
        limit = total

    count = 0

    shodan_parser = ShodanParser()

    logger.info("Creating mongodb client.")
    with MongoClient() as client:
        logger.info(f"Client created {client}")

        mongoDBConnection = f"mongodb://{client.HOST}:{client.address[1]}/shodan"

        # Connect our ORM to the in-memory pymongo
        connect(host=mongoDBConnection)

        # TODO: Load/Save this file in the users home directory.
        # if os.path.exists("./cve_data.json"):
        #    shodan_parser.load_cve_json()

        def save(partial: bool = False):
            shodan_parser.save_to_db()
            if partial and output_partial_summary == False:
                return
            if partial and output_partial_summary:
                print("Outputting partial file!", end="\r")
            else:
                print(f"Outputting file to {filename}!")
            shodan_parser.output_computer_summary(file_loc=filename, file_type=FileType.json)
        try:
            logger.info("Get search cursors.")
            print(f"Loading results...", end="\r")
            cursor = api.search_cursor(query, minify=False)

            i = 1
            # Save every x results.
            save_every = 1000

            for cur in cursor:
                sys.stdout.write(
                    f"                                                                                \r")
                print(f"Line: {i}/{limit}", end="\r")
                line = json.dumps(cur) + '\n'
                shodan_parser.add_line(line=line)

                if i % save_every == 0:
                    save(True)

                # Stop parsing
                if i >= limit:
                    print(f"Line: {i}/{limit}")
                    break
                i += 1

        except shodan.APIError as e:
            logger.exception(f"api info returned error! Error: {e}")
            logger.info("Saving what data we currently have!")
            save()

        except Exception as e:
            logger.exception(f"Unknown exception occured! {e}")
            sys.exit()

        save()


@cli.command(help="Set shodan key.")
@click.argument("shodan_key", metavar="<SHODAN KEY>")
def init(shodan_key):
    """
    Function to set the shodan key to config
    :param shodan_key:
    :return:
    """
    # Check if API key is legit.
    try:
        logger.info("Getting API info for provided key.")
        api_info = shodan.Shodan(shodan_key).info()
        logger.info(f"SUCCESS: {api_info}")
    except shodan.exception.APIError:
        logger.exception("Invalid API Key")
        click.ClickException("Invalid API key provided!").show()
        sys.exit(1)

    cli_handler.config.set("SHODAN", "api_key", shodan_key)
    cli_handler.save_config()

@cli.command(help="Removes your api key from the config")
def remove_key():
    cli_handler.config.remove_option("SHODAN", "api_key")
    cli_handler.save_config()

if __name__ == "__main__":
    # parse_files()
    cli()

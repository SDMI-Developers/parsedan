import gzip
import json
import logging
import os
import sys
import shodan
import click
from pathlib import Path
from parsedan.CLI_Handler import CLIHandler

# Logging configuration
import logging
import logging.handlers

from parsedan.ShodanParser import FileType, ShodanParser

home_dir = os.path.join(str(Path.home()), ".parsedan")

# Make sure this directory
Path(home_dir).mkdir(exist_ok=True)
logger = logging.getLogger("Parsedan." + __name__)


def _set_log_config(level):
    logging.basicConfig(filename=f"{home_dir}/output.log", level=level,
                        format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')


if __name__ == "__main__":
    _set_log_config(logging.INFO)


cli_handler = CLIHandler(dir=home_dir)


@click.group()
@click.option('--d', 'debug_option', help="Set logging level to debug mode", count=True)
def cli(debug_option):
    # Set to logging level debug if specified
    if debug_option:
        logging.root.setLevel(logging.DEBUG)


def _query_shodan_api(api: shodan, query: str) -> int:
    """Querys the shodan API for info on the provided api key

    Args:
        api (shodan): a shodan object
        query (str): The query for the shodan api

    Returns:
        int: total number of results that can be queried
    """
    logger.info("Querying API.")
    print("Querying Shodan API...", end="\r")
    try:
        # TODO: Make a timeout function since this seems to not timeout on its own.
        total = api.count(query)['total']
        info = api.info()

        logger.info(f"Got total and api info: {total} {info}")
    except Exception:
        logger.exception("api info returned error!")
        raise click.ClickException(
            'The Shodan API is unresponsive at the moment, please try again later.')
    # Erase previous line
    _erase_line()

    # Print some summary information about the download request
    click.echo('Search query:\t\t\t{}'.format(query))
    click.echo('Total number of results:\t{}'.format(total))
    click.echo('Query credits left:\t\t{}'.format(info['unlocked_left']))

    return total


def _erase_line():
    """
    Shortcut to erase entire console line
    """
    print("\033[K", end="\r")


@cli.command()
@click.option('--output-original/--no-output-original', help="Output the original data that is returned from shodan into a seperate json file. DEFAULT: False", default=False)
@click.option('--output-partial-summary/--no-output-partial-summary', help="Output the summary to json/csv file every 1000 results. May slow down the operation once file starts to get big. DEFAULT: False", default=False)
@click.option('--limit', help='The number of results you want to download. -1 to download all the data possible. DEFAULT: -1', default=-1, type=int)
# @click.option('--whitelist-file', help='Provide a location to a newline delimited file of ip ranges you want to make as important.', default=None, type=str)
@click.option('--filetype', help='Type of file to create, options are "csv", "json", or "both". Default "both"', default="both", type=str)
@click.option('--reset-db/--no-reset-db', help="Whether to reset the database. DEFAULT: False", default=False)
@click.argument('output-filename', metavar='<filename>')
@click.argument('query', metavar='<search query>', nargs=-1)
def start(output_original, output_partial_summary, limit, filetype: str, reset_db: bool, output_filename, query):
    logger.info("Called start with options - " + str(locals()))
    cli_handler.echo_header()

    logger.info("Reading config file for shodan api key")

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

    output_filename = output_filename.strip()
    if output_filename == '':
        logger.exception("Empty filename")
        raise click.ClickException('Empty filename')

    # Check if appropiate file type was provided.
    filetype = filetype.lower()
    if filetype not in ["csv", "json", "both"]:
        logger.exception(f"Invalid file type: {filetype}")
        raise click.ClickException(f"Invalid file type: {filetype}")

    # Remove .csv or .json if it was added. This gets added by our output function
    output_filename.replace(".json", "")
    output_filename.replace(".csv", "")

    total = _query_shodan_api(api, query)

    # Cant have a limit greater then total
    if limit > total:
        limit = total

    # A limit of -1 means that we should download all the data
    if limit <= 0:
        logger.debug("Setting limit to total.")
        limit = total

    shodan_parser = ShodanParser(
        connection_string=f"sqlite:///{home_dir}/parsedan.db")

    # Reset the database if param supplied
    if reset_db:
        shodan_parser.db_Handler._clear_db()

    try:
        def _save(partial: bool = False):
            logger.info("Saving data!")
            shodan_parser.save_to_db()
            if partial and output_partial_summary is False:
                return
            if partial and output_partial_summary:
                print("Outputting partial file!", end="\r")
            else:
                print(f"Outputting file to {output_filename}!")
            shodan_parser.output_computer_summary(
                file_loc=output_filename, file_type=FileType.str_to_enum(filetype))

        logger.info("Get search cursors.")
        print(f"Loading results...", end="\r")
        cursor = api.search_cursor(query, minify=False)
        # Clearing previous line
        _erase_line()
        i = 1
        # Save every x results.
        save_every = 1000

        # Output the original shodan GZIPPED file
        if output_original:
            gzipped_file_loc = "_shodan_" + output_filename + ".gz"
            logger.info(f"Opening GZIPPed file at {gzipped_file_loc}")
            fout = gzip.open(gzipped_file_loc, 'w')

        # Loop over results from shodan
        for cur in cursor:
            print(f"Line: {i}/{limit}", end="\r")

            shodan_parser.add_line(line=cur)
            if i % save_every == 0:
                _save(partial=True)

            if output_original:
                line = json.dumps(cur) + '\n'
                logger.debug("Writing line to gziped file")
                fout.write(line.encode('utf-8'))

            # Stop parsing
            if i >= limit:
                logger.info("Limit hit, done parsing!")
                print(f"Line: {i}/{limit}")
                _save()
                break
            i += 1

        if output_original:
            logger.debug("Closing gzip writer")
            fout.close()
    except shodan.APIError as e:
        logger.exception(f"api info returned error! Error: {e}")
        logger.info("Saving what data we currently have!")
        _save()
    except Exception as e:
        logger.exception(f"Unknown exception occured! {e}")
        sys.exit()


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
    logger.info("Removing api key from config file.")
    cli_handler.config.remove_option("SHODAN", "api_key")
    cli_handler.save_config()


if __name__ == "__main__":
    cli()

import os
import pathlib
from setuptools import setup, Command

# Useful for having a seperate README file.
# The directory containing this file
HERE = pathlib.Path(__file__).parent

#The text of the README file
README = (HERE / "README.md").read_text()

with open('requirements.txt') as f:
    """
    Open and parse the requirements.txt file to put into install_requires
    """
    required = f.read().splitlines()

class CleanCommand(Command):
    """Custom clean command to tidy up the project root."""
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        os.system('rm -vrf ./build ./dist ./*.pyc ./*.tgz ./*.egg-info')

setup(
    name="parsedan",
    version="0.1.1b01",
    description="A shodan parser that given a query will download results and parse them into CSV or JSON files while also scoring them.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/SDMI-Developers/parsedan",
    author="Louisiana State University at Stephenson Disaster Management Institute",
    author_email="sdmidev@lsu.edu",
    license="MIT",
    classifiers=[],
    packages=["parsedan", "parsedan.db"],
    include_package_data=True,
    install_requires=required,
    cmdclass={
        'clean': CleanCommand,
    },
    entry_points='''
        [console_scripts]
        parsedan=parsedan.__main__:cli
    '''
)

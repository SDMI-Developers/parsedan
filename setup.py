import pathlib
from setuptools import setup

# The directory containing this file
#HERE = pathlib.Path(__file__).parent

# The text of the README file
#README = (HERE / "README.md").read_text()
with open('requirements.txt') as f:
    required = f.read().splitlines()

# This call to setup() does all the work
setup(
    name="parsedan",
    version="0.0.1",
    description="A shodan parser that given a query will download results and parse them into CSV or JSON files while also scoring them.",
    long_description="README",
    long_description_content_type="text/markdown",
    url="",
    author="Louisiana State University at Stephenson Disaster Management Institute",
    author_email="sdmidev@lsu.edu",
    license="MIT",
    classifiers=[],
    packages=["parsedan", "parsedan.db"],
    include_package_data=True,
    install_requires=required,
)

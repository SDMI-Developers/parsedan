import datetime
from bson.json_util import default
from mongoengine import *
from mongoengine import Document
from mongoengine.document import EmbeddedDocument
from mongoengine.fields import (
    BooleanField,
    DateField,
    DateTimeField,
    DecimalField,
    EmbeddedDocumentListField,
    FloatField,
    IntField,
    LazyReferenceField,
    ListField,
    StringField,
)


class Job(Document):
    meta = {"collection": "jobs"}
    description = StringField()
    status = StringField()

    # -1 failed, 0 running, 1 finished
    status_code = IntField(choices=(-1, 0, 1))
    start_time = DateTimeField(required=True)
    finish_time = DateTimeField()


class ParsedFile(Document):
    meta = {"collection": "parsed_files"}
    filename = StringField()
    datetime_parsed = DateTimeField(default=datetime.datetime.now())
    file_md5 = StringField()


class CVEHistory(EmbeddedDocument):
    cveName = StringField()
    date_observed = DateField()

class PortHistory(EmbeddedDocument):
    port = IntField()
    description = ListField()
    tcp = BooleanField(default=False)
    udp = BooleanField(default=False)
    date_observed = DateField()


class ScoreHistory(EmbeddedDocument):
    score = DecimalField()
    date_observed = DateField()


class CVE(Document):
    """
    This mongo model is responsible for storing the NIST CVE data. Each entry is a entry
    from nists own database and allows us to always have the most up-to-date nist-data.
    """

    meta = {"collection": "nist_cves"}
    cveName = StringField(primary_key=True)
    cvss20 = FloatField(precision=2)
    cvss30 = FloatField(precision=2)
    summary = StringField()
    lastModifiedDate = DateField()
    publishedDate = DateField()


class WhitelistRange(Document):
    meta = {"collection": "whitelist_ranges"}
    desc = StringField()
    rangeString = StringField(primary_key=True)
    minDecimal = IntField()
    maxDecimal = IntField()

class DataSource(Document):
    '''
    Data source is used to determine where exactly the data came from.
    
    Example: If data came from Shodan/LSP then it would be under that data source, if it came
    from Bernhard, then it fall under that source.
    '''
    meta = {"collection": "data_sources"}
    name = StringField(null=False)
    date_added = DateField(null=False)


class Role(Document):
    meta = {"collection": "roles"}
    role_name = StringField()


class User(Document):
    meta = {"collection": "users"}
    f_name = StringField()
    l_name = StringField()
    date_created = DateField()
    roles = ListField(LazyReferenceField(Role))


class VulnerableComputer(Document):
    meta = {"collection": "vulnerable_computers"}
    data_source = LazyReferenceField(DataSource)
    ip = FloatField(required=True, precision=0, primary_key=True)
    asn = StringField()
    ip_str = StringField()
    os = StringField()
    isp = StringField()
    org = StringField()
    is_whitelisted = BooleanField(default=False)
    date_added = DateField()
    city = StringField()
    state = StringField()
    lat = FloatField(precision=4)
    lng = FloatField(precision=4)
    country = StringField
    current_score = FloatField(precision=2, default=0)
    high_score = FloatField(precision=2, default=0)
    port_history = EmbeddedDocumentListField(PortHistory)
    cve_history = EmbeddedDocumentListField(CVEHistory)

class Vulnerabilities(Document):
    meta = {"collection": "vulnerabilities"}
    data_source = LazyReferenceField(DataSource)
    CVE = StringField()
    Host = StringField()
    Protocol = StringField()
    Port = FloatField(precision=0)
    Name = StringField()
    Synopsis = StringField()
    score = FloatField()
    timestamp = DateField()
    time_processed = DateField()
    id = FloatField(required=True, precision=0, primary_key=True)
    HighestScore = FloatField()
    TotalScore = FloatField()
    AverageScore = FloatField()
    NumVulnPorts = FloatField()
    AggregateVuln = FloatField()
    SumScore = FloatField()
    SumPorts = FloatField()
from email.policy import default
import enum
import json
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Boolean, Date, Enum, null
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.ext.declarative import DeclarativeMeta


Base = declarative_base()


class JobStatus(enum.Enum):
    fail = -1
    running = 0
    finished = 1


class Job(Base):
    __tablename__ = 'jobs'
    id = Column(Integer, primary_key=True)
    description = Column(String)
    status_msg = Column(String)
    status_code = Column(Enum(JobStatus))


class ParsedFile(Base):
    __tablename__ = 'parsed_files'
    id = Column(Integer, primary_key=True)
    filename = Column(String)
    datetime_parsed = Column(DateTime)
    file_md5 = Column(String, unique=True)


class CVEHistory(Base):
    __tablename__ = 'cve_history'
    cve_name = Column(String, primary_key=True)
    date_observed = Column(Date, primary_key=True)
    computer_id = Column(Float, ForeignKey("computers.ip"), primary_key=True)
    computer = relationship("Computer", back_populates="cve_history")

    def as_dict(self):
        return {c.name: getattr(self, c.name)
                for c in self.__table__.columns}


class PortHistory(Base):
    __tablename__ = 'port_history'
    port = Column(Integer, primary_key=True)
    description = Column(String)
    date_observed = Column(Date, primary_key=True)
    computer_id = Column(Float, ForeignKey("computers.ip"), primary_key=True)
    udp = Column(Boolean)
    tcp = Column(Boolean)
    computer = relationship("Computer", back_populates="port_history")

    def as_dict(self):
        return {c.name: getattr(self, c.name)
                for c in self.__table__.columns}

    def composite_key(self):
        return (self.port, self.date_observed, self.computer_id)


class Computer(Base):
    __tablename__ = 'computers'
    ip = Column(Float(precision=0), primary_key=True)
    asn = Column(String)
    city = Column(String)
    state = Column(String)
    os = Column(String)
    isp = Column(String)
    org = Column(String)
    lat = Column(Float(precision=4))
    lng = Column(Float(precision=4))
    score = Column(Float(precision=2))
    country = Column(String)
    # TODO: Make this a calculated value??
    ip_str = Column(String)

    date_added = Column(Date)

    cve_history = relationship("CVEHistory", back_populates="computer")
    port_history = relationship("PortHistory", back_populates="computer")

    def as_dict(self):
        computer = {c.name: getattr(self, c.name)
                    for c in self.__table__.columns}
        computer["port_history"] = [p.as_dict() for p in self.port_history]
        computer["cve_history"] = [p.as_dict() for p in self.cve_history]
        return computer


class CVE(Base):
    """
    This mongo model is responsible for storing the NIST CVE data. Each entry is a entry
    from nists own database and allows us to always have the most up-to-date nist-data.
    """
    __tablename__ = 'nist_cves'
    cve_name = Column(String, primary_key=True)
    cvss_20 = Column(Float(precision=2), default=None)
    cvss_30 = Column(Float(precision=2), default=None)
    summary = Column(String)
    last_modified_date = Column(Date)
    published_date = Column(Date)

from datetime import datetime
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Boolean, create_engine, Date
from sqlalchemy.orm import declarative_base, sessionmaker, relationship


Base = declarative_base()


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


class PortHistory(Base):
    __tablename__ = 'port_history'
    port = Column(Integer, primary_key=True)
    description = Column(String)
    date_observed = Column(Date, primary_key=True)
    computer_id = Column(Float, ForeignKey("computers.ip"), primary_key=True)
    udp = Column(Boolean)
    tcp = Column(Boolean)
    computer = relationship("Computer", back_populates="port_history")

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

    # TODO: Make this a calculated value??
    ip_str = Column(String)

    date_added = Column(Date)

    cve_history = relationship("CVEHistory", back_populates="computer")
    port_history = relationship("PortHistory", back_populates="computer")


# class ScoreHistory(Base):
#     __tablename__ = 'score_history'
#     score = Column(Float(precision=2))
#     date_observed = Column(Date)


class CVE(Base):
    """
    This mongo model is responsible for storing the NIST CVE data. Each entry is a entry
    from nists own database and allows us to always have the most up-to-date nist-data.
    """
    __tablename__ = 'nist_cves'
    cve_name = Column(String, primary_key=True)
    cvss_20 = Column(Float(precision=2))
    cvss_30 = Column(Float(precision=2))
    summary = Column(String)
    last_modified_date = Column(Date)
    published_date = Column(Date)

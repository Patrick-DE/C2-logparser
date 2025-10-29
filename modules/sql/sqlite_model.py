import re, enum
from sqlalchemy import Column, DateTime, Integer, String, Enum, Table
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql.schema import ForeignKey
from modules.utils import excel_save, redact

class EntryType(enum.Enum):
      metadata = 1
      input = 2
      task = 3
      checkin = 4
      output = 5
      note = 6
      error = 7
      indicator = 8
      job_registered = 9
      job_completed = 10
      # custom attributes
      download = 11
      upload = 12
      events = 13
      warning = 14
      event = 15
      # brute ratel
      http_request = 16
      http_log = 17
      access_denied = 18	


Base = declarative_base()

class Beacon(Base):
      """
      Table definition for the SQLite DB
      """
      __tablename__ = "beacon"
      id = Column(Integer, primary_key= True)
      ip = Column(String, unique=False)
      ip_ext = Column(String, nullable=True)
      hostname = Column(String, nullable=True)
      user =  Column(String, nullable=True)
      process = Column(String, nullable=True)
      pid = Column(Integer, nullable=True)
      os = Column(String, nullable=True)
      version = Column(String, nullable=True)
      build = Column(String, nullable=True)
      arch = Column(String, nullable=True)
      timestamp = Column(DateTime, nullable=False)
      timezone = Column(String)
      entries = relationship("Entry", back_populates="parent",lazy='joined', join_depth=1)
      # for OST
      uid_str = Column(String, nullable=True, unique=True, index=True) # For OST C2 beacon tracking
      
      @property
      def joined(self):
            if self.entries:
                  return self.entries[0].timestamp
            return self.timestamp 
      @property
      def exited(self):
            if self.entries:
                  return self.entries[-1].timestamp
            return self.timestamp

      def is_high_integrity(self):
            if "*" in self.user:
                  return True
            else:
                  return False

      def to_row(self):
            return [self.hostname, \
                  self.ip, \
                  self.ip_ext, \
                  self.user, \
                  self.process, \
                  self.pid, \
                  self.joined, \
                  self.exited]
      

class Entry(Base):
      """
      Table definition for the SQLite DB
      """
      __tablename__ = "entry"
      id = Column(Integer, primary_key = True)
      timestamp = Column(DateTime)
      timezone = Column(String)
      type = Column(Enum(EntryType))
      operator = Column(String, nullable=True)
      ttp = Column(String, nullable=True)
      content = Column(String)
      parent_id = Column(Integer, ForeignKey('beacon.id'))
      parent = relationship("Beacon", back_populates="entries", lazy="joined", join_depth=1)
      # for OST
      task_uid = Column(String, nullable=True, index=True) # For OST C2 task tracking

      #def __getattribute__(self, item):
      #      if item == "content" and self.type == EntryType.input:
      #            return re.sub(r"\s*<.*>\s*(.*)", "", self.content).group(1)

      # def get_input(self):
      #       if self.type == EntryType.input or self.type == EntryType.task:
      #             return re.sub(r"\s*<.*?>\s*(.*)", r"\1", self.content)
      #       else:
      #             raise ValueError("This function can only be called with EntryType.input or EntryType.task")

      def to_row(self, redacting=True):
            hostname, user, ip = "","",""
            if redacting:
                  content = excel_save(redact(self.content))
            else:
                  content = excel_save(self.content)

            date = self.timestamp.strftime("%d/%m/%y")
            time = self.timestamp.strftime("%H:%M")
            b = self.parent
            if b:
                  hostname, user, ip = b.hostname, b.user, b.ip
            return [date, time, hostname, content, user, ip]


# class Action(Base):
#       """
#       Table definition for the SQLite DB
#       """
#       __tablename__ = "action"
#       id = Column(Integer, primary_key = True)
#       input_id = Column(Integer, ForeignKey("entry.id"))
#       task_id = Column(Integer, ForeignKey("entry.id"))
#       output_id = Column(Integer, ForeignKey("entry.id"))

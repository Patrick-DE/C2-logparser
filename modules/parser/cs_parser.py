import os
import re
from typing import List, Dict
from sqlalchemy.orm import exc, relationship
from sqlalchemy import select, and_, Column, DateTime, Integer, String, Enum, ForeignKey
from modules.sql.sqlite_func import init_db
from modules.sql.sqlite_model import EntryType, Beacon, Entry
import threading
from datetime import datetime

class CSLogParser:
    def __init__(self, filepath: str, db_path: str, debug: bool = False):
        self.filepath = filepath
        # Extract beacon ID from the filename
        self.beacon_id = self.extract_beacon_id_from_filename(filepath)
        # Extract date from the folder name
        self.year_prefix = self.extract_year_prefix_from_filepath(filepath)
        # Initialize the database session
        session_manager = init_db(db_path, debug)
        self.session = session_manager()
        # Track the current command and its accumulated output
        self.last_command = None
        self.current_output = ""
        self.is_accumulating_output = False
        # Lock for thread-safe database access
        self.lock = threading.Lock()
        # Track number of entries added to database
        self.entries_added = 0

    @staticmethod
    def extract_beacon_id_from_filename(filename: str) -> int:
        match = re.search(r'beacon_(\d+)', filename)
        if match:
            return int(match.group(1))
        elif "events" in filename or "downloads" in filename:
            return 0
        else:
            #raise ValueError("Beacon ID could not be extracted from the filename.")
            print(f"Beacon ID could not be extracted from the filename: {filename}")
            return -1

    @staticmethod
    def extract_year_prefix_from_filepath(filepath: str) -> str:
        match = re.search(r'(\d{6})', os.path.dirname(filepath))
        if match:
            return match.group(1)[:2]
        else:
            raise ValueError("Year prefix could not be extracted from the folder name.")

    @staticmethod
    def parse_beacon_log(filepath: str, db_path: str, debug: bool = False):
        if filepath.endswith("weblog_443.log"):
            return 0
        parser = CSLogParser(filepath, db_path, debug)
        parser.parse()
        return parser.entries_added

    @staticmethod
    def parse_timestamp(year_prefix: str, timestamp_str: str) -> datetime:
        # get the current year
        return datetime.strptime(year_prefix + "/" + timestamp_str, "%y/%m/%d %H:%M:%S %Z")


    def parse(self):
        with open(self.filepath, 'r') as file:
            for line in file:
                current_command = self.parse_line(line)
                if current_command and self.is_accumulating_output and current_command['type'] != 'output':
                    # store the output of the previous command
                    if self.last_command:
                        self.store_entry_to_db({'type': 'output', 'timestamp': self.last_command['timestamp'], 'timezone': self.last_command["timezone"], 'content': self.current_output.strip()})
                        self.current_output = ""
                    self.is_accumulating_output = False
                    self.last_command = current_command
                if current_command:
                    # Handle metadata separately to store or update beacon information
                    if current_command['type'] == 'metadata':
                        self.store_beacon_to_db(current_command)
                    # if new command is found, store the new command and the old output
                    elif current_command['type'] == 'input':
                        # store finished entry with its output
                        if self.is_accumulating_output:
                            self.store_entry_to_db({'type': 'output', 'timestamp': self.last_command['timestamp'], 'timezone': self.last_command["timezone"], 'content': self.current_output.strip()})
                            self.current_output = ""
                            self.is_accumulating_output = False
                        # if self.current_output:
                        #     self.store_entry_to_db({'type': 'output', 'timestamp': self.current_command['timestamp'], 'timezone': self.current_command["timezone"], 'content': self.current_output.strip()})
                        
                        self.store_entry_to_db(current_command)
                        # Reset for the new command
                        self.last_command = current_command
                    elif current_command['type'] == 'output' or current_command['type'] == 'received_output' or current_command['type'] == 'error':
                        # Accumulate output for the current command
                        self.is_accumulating_output = True
                        self.current_output += current_command['content']
                    else:
                        # Store any other type of entry immediately
                        if self.last_command and self.current_output:
                            self.store_entry_to_db({'type': 'output', 'timestamp': self.last_command['timestamp'], 'timezone': self.last_command["timezone"], 'content': self.current_output.strip()})
                            self.last_command = None
                            self.current_output = ""
                            self.is_accumulating_output = False
                        self.store_entry_to_db(current_command)
                else:
                    # add the output to the current command
                    if self.is_accumulating_output:
                        self.current_output += line
                    elif re.match(r'^\s*$', line):
                        continue
                    elif "events.log" in self.filepath:
                        pass
                    else:
                        print(f"Could not parse {self.filepath} - {line}")
            # Last line of the file: Store the last command of the file and its output if applicable
            if self.current_output:
                if self.last_command:
                    self.store_entry_to_db({'type': 'output', 'timestamp': self.last_command['timestamp'], 'timezone': self.last_command["timezone"], 'content': self.current_output.strip()})
                if current_command:
                    self.store_entry_to_db({'type': 'output', 'timestamp': current_command['timestamp'], 'timezone': current_command["timezone"], 'content': self.current_output.strip()})

    def parse_line(self, line: str) -> Dict:
        # Regular expressions for different log formats
        metadata_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[metadata\] (?P<ip_ext>[\w\.\_]+) (?P<direction><-|->) (?P<ip_int>[\d\.]+); computer: (?P<hostname>.*?); user: (?P<user>.*?); process: (?P<process>.*?); pid: (?P<pid>\d+); os: (?P<os>.*?); version: (?P<version>.*?); build: (?P<build>.*?); beacon arch: (?P<arch>.*)')
        input_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[input\] <(?P<operator>.*?)> (?P<command>.*)')
        output_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[output\](?P<output>.*)')
        task_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[task\] <(?P<operator>.*?)> (?P<task_description>.*)')
        checkin_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[checkin\] host called home, sent: (?P<bytes_sent>\d+) bytes')
        received_output_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[output\]\s*received output:')
        download_pattern = re.compile(r'^(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+))\t(?P<source_ip>[\d\.]+)\t(?P<session_id>\d+)\t(?P<size>\d+)\t(?P<server_path>[^\t]+)\t(?P<file_name>[^\t]+)\t(?P<local_path>[^\t]*)\r?\n')
        job_registered_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[job_registered\] job registered with id (?P<job_id>\d+)')
        job_completed_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[job_completed\] job (?P<job_id>\d+) completed')
        indicator_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[indicator\] (?P<content>file: (?P<file_hash>\w+) (?P<file_size>\d+) bytes (?P<file_path>.+))')
        event_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \*\*\* (?P<event_description>.*)')
        error_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[error\] (?P<error_message>.*)')
        note_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[note\] (?P<note_message>.*)')
        warning_pattern = re.compile(r'(?P<timestamp>\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[warning\] (?P<warning_message>.*)')

        metadata_match = metadata_pattern.match(line)
        input_match = input_pattern.match(line)
        output_match = output_pattern.match(line)
        task_match = task_pattern.match(line)
        checkin_match = checkin_pattern.match(line)
        received_output_match = received_output_pattern.match(line)
        event_match = event_pattern.match(line)
        download_match = download_pattern.match(line)
        error_match = error_pattern.match(line)
        job_registered_match = job_registered_pattern.match(line)
        job_completed_match = job_completed_pattern.match(line)
        indicator_match = indicator_pattern.match(line)
        note_match = note_pattern.match(line)
        warning_match = warning_pattern.match(line)

        if metadata_match:
            return {
                'type': 'metadata',
                'timestamp': self.parse_timestamp(self.year_prefix, metadata_match.group('timestamp')),
                'ip': metadata_match.group('ip_int'),
                'ip_ext': metadata_match.group('ip_ext'),
                'hostname': metadata_match.group('hostname'),
                'user': metadata_match.group('user'),
                'process': metadata_match.group('process'),
                'pid': metadata_match.group('pid'),
                'os': metadata_match.group('os'),
                'version': metadata_match.group('version'),
                'build': metadata_match.group('build'),
                'arch': metadata_match.group('arch'),
            }
        elif input_match:
            return {
                'type': 'input',
                'timestamp': self.parse_timestamp(self.year_prefix, input_match.group('timestamp')),
                'timezone': input_match.group('timezone'),
                'operator': input_match.group('operator'),
                'content': input_match.group('command'),
            }
        elif output_match:
            return {
                'type': 'output',
                'timestamp': self.parse_timestamp(self.year_prefix, output_match.group('timestamp')),
                'timezone': output_match.group('timezone'),
                'content': output_match.group('output').strip(),
            }
        elif task_match:
            return {
                'type': 'task',
                'timestamp': self.parse_timestamp(self.year_prefix, task_match.group('timestamp')),
                'timezone': task_match.group('timezone'),
                'ttp': task_match.group('operator'),
                'content': task_match.group('task_description'),
            }
        elif checkin_match:
            return {
                'type': 'checkin',
                'timestamp': self.parse_timestamp(self.year_prefix, checkin_match.group('timestamp')),
                'timezone': checkin_match.group('timezone'),
                'content': checkin_match.group('bytes_sent'),
            }
        elif received_output_match:
            return {
                'type': 'received_output',
                'timestamp': self.parse_timestamp(self.year_prefix, received_output_match.group('timestamp')),
                'timezone': received_output_match.group('timezone'),
            }
        elif event_match:
            return {
                'type': 'event',
                'timestamp': self.parse_timestamp(self.year_prefix, event_match.group('timestamp')),
                'timezone': event_match.group('timezone'),
                'content': event_match.group('event_description').strip(),
            }
        elif download_match:
            return {
                'type': 'download',
                'timestamp': self.parse_timestamp(self.year_prefix, download_match.group('timestamp')),
                'timezone': download_match.group('timezone'),
                'content': "IP: {}, File: {}{}, Size: {}".format(download_match.group('source_ip'), download_match.group('local_path'), download_match.group('file_name'), download_match.group('size')),
                #'content': download_match.group('content').strip(),
                # 'source_ip': download_match.group('source_ip'),
                # 'session_id': download_match.group('session_id'),
                # 'size': download_match.group('size'),
                # 'server_path': download_match.group('server_path'),
                # 'file_name': download_match.group('file_name'),
                # 'local_path': download_match.group('local_path'),
            }
        elif error_match:
            return {
                'type': 'error',
                'timestamp': self.parse_timestamp(self.year_prefix, error_match.group('timestamp')),
                'timezone': error_match.group('timezone'),
                'content': error_match.group('error_message').strip(),
            }
        elif job_registered_match:
            return {
                'type': 'job_registered',
                'timestamp': self.parse_timestamp(self.year_prefix, job_registered_match.group('timestamp')),
                'timezone': job_registered_match.group('timezone'),
                'content': job_registered_match.group('job_id').strip(),
            }
        elif job_completed_match:
            return {
                'type': 'job_completed',
                'timestamp': self.parse_timestamp(self.year_prefix, job_completed_match.group('timestamp')),
                'timezone': job_completed_match.group('timezone'),
                'content': job_completed_match.group('job_id').strip(),
            }
        elif indicator_match:
            return {
                'type': 'indicator',
                'timestamp': self.parse_timestamp(self.year_prefix, indicator_match.group('timestamp')),
                'timezone': indicator_match.group('timezone'),
                'content': "MD5: {}, File: {}, Size: {}".format(indicator_match.group('file_hash'), indicator_match.group('file_path'), indicator_match.group('file_size')),
                #'content': indicator_match.group('content').strip(),
                # 'file_hash': indicator_match.group('file_hash'),
                # 'file_size': indicator_match.group('file_size'),
                # 'file_path': indicator_match.group('file_path').strip(),
            }
        elif note_match:
            return {
                'type': 'note',
                'timestamp': self.parse_timestamp(self.year_prefix, note_match.group('timestamp')),
                'timezone': note_match.group('timezone'),
                'content': note_match.group('note_message').strip(),
            }
        elif warning_match:
            return {
                'type': 'note',
                'timestamp': self.parse_timestamp(self.year_prefix, warning_match.group('timestamp')),
                'timezone': warning_match.group('timezone'),
                'content': warning_match.group('warning_message').strip(),
            }
        return None

    def store_entry_to_db(self, entry_data: Dict):
        entry_type = EntryType[entry_data['type']]
        entry_data['parent_id'] = self.beacon_id
        try:
            # Sanity check to avoid adding duplicate entries
            with self.lock:
                existing_entry = self.session.query(Entry).filter_by(
                    timestamp=entry_data['timestamp'],
                    timezone=entry_data['timezone'],
                    type=entry_type,
                    parent_id=self.beacon_id,
                    content=entry_data['content']
                ).one_or_none()

                if existing_entry is None:
                    entry = Entry(**entry_data)
                    self.session.add(entry)
                    self.entries_added += 1
                else:
                    # update the entry object
                    existing_entry.ttp = entry_data['ttp'] if 'ttp' in entry_data else None
                    existing_entry.operator = entry_data['operator'] if 'operator' in entry_data else None
                    existing_entry.content = entry_data['content'] if 'content' in entry_data else None
                    self.session.add(existing_entry)
                    
                self.session.commit()
        except Exception as e:
            self.session.rollback()
            print(f"Failed to insert log entry: {e}")

    def store_beacon_to_db(self, metadata: Dict):
        #remove type from metadata
        metadata.pop('type', None)
        try:
            # Sanity check to avoid adding duplicate beacons
            with self.lock:
                existing_beacon = self.session.query(Beacon).filter_by(
                    id=self.beacon_id
                ).one_or_none()

                if existing_beacon is None:
                    beacon = Beacon(**metadata, id=self.beacon_id)
                    self.session.add(beacon)
                else:
                    existing_beacon.ip = metadata['ip']
                    existing_beacon.ip_ext = metadata['ip_ext']
                    existing_beacon.hostname = metadata['hostname']
                    existing_beacon.user = metadata['user']
                    existing_beacon.process = metadata['process']
                    existing_beacon.pid = metadata['pid']
                    existing_beacon.os = metadata['os']
                    existing_beacon.version = metadata['version']
                    existing_beacon.build = metadata['build']
                    existing_beacon.arch = metadata['arch']
                    existing_beacon.timestamp = metadata['timestamp']
                    self.session.add(existing_beacon)
                    
                self.session.commit()
        except Exception as e:
            self.session.rollback()
            print(f"Failed to insert or update beacon: {e}")

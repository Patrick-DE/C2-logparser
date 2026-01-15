import re
from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, create_engine
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from typing import Dict
from modules.sql.sqlite_func import init_db
from modules.sql.sqlite_model import Beacon, Entry, EntryType
from modules.utils import extract_ips

####
# Disclaimer: There are some issues with BR logs which I tried to work around!
# - There is no mapping between input and output
# - Some of the logs just don't have a beacon reference, especially upload and http_request
# - The timestamp is not always in the same format
# - Autoruns are too fast for different timestamps, so we need to add a microsecond to the timestamp >:/ FFS
# - There are multiple outputs in one, so I have to create the same output object again with new content
# - There are other logs interfering with the output
####
class BRLogParser:
    def __init__(self, filepath: str, db_path: str, debug: bool = False):
        self.filepath = filepath
        # Extract beacon ID from the filename
        self.beacon_id = self.extract_beacon_id_from_filename(filepath)
        # Initialize the database session
        session_manager = init_db(db_path, debug)
        self.session = session_manager()
        # Track the current command and its accumulated output
        self.current_command = None
        self.current_output = ""
        self.is_accumulating_output = False
        # Lock for thread-safe database access
        self.lock = threading.Lock()
        # Track number of entries added to database
        self.entries_added = 0
        
    @staticmethod
    def extract_beacon_id_from_filename(filename: str) -> int:
        match = re.search(r'b-(\d+)', filename)
        if match:
            return int(match.group(1))
        else:
            pass

    @staticmethod
    def parse_beacon_log(filepath: str, db_path: str, debug: bool = False):
        parser = BRLogParser(filepath, db_path, debug)
        parser.parse()
        return parser.entries_added
        
    @staticmethod
    def parse_timestamp(timestamp_str: str, format: str = "%Y/%m/%d %H:%M:%S %Z") -> datetime:
        # get the current year
        try:
            return datetime.strptime(timestamp_str, format)
        except ValueError:
            raise ValueError("Incorrect data format!")
            

    def parse(self):
        with open(self.filepath, 'r') as file:
            for line in file:
                parsed_line = self.parse_line(line)
                if parsed_line:
                    # Handle metadata separately to store or update beacon information
                    if parsed_line['type'] == 'metadata':
                        self.store_beacon_to_db(parsed_line)
                    elif parsed_line['type'] == 'output_end':
                        # store completed output if there is something to write
                        if self.current_output:
                            self.store_entry_to_db({'type': self.current_command['type'], 'timestamp': self.current_command['timestamp'], 'timezone': self.current_command["timezone"], 'content': self.current_output.strip()})
                        self.current_output = ""
                        self.is_accumulating_output = False
                    # handle multiline output
                    elif parsed_line['type'] == 'output' or parsed_line['type'] == 'access_denied' or parsed_line['type'] == 'http_request' or parsed_line['type'] == 'http_log':
                        # if a new command is detected, store the previous command and its output and reset current_output
                        if self.is_accumulating_output:
                            self.current_command['content'] = self.current_output.strip()
                            self.store_entry_to_db(self.current_command)
                            self.current_output = ""
                        
                        # Start/restart the accumulate output for the current command
                        self.is_accumulating_output = True
                        self.current_command = parsed_line
                        self.current_output += parsed_line['content'] if 'content' in parsed_line else ""
                    else:
                        # handle if there is other stuff between the output start and the first line of the output
                        # lets hope it does not start randomly in between the output
                        if self.current_output == "" and self.is_accumulating_output:
                            self.store_entry_to_db(parsed_line)
                            continue
                        
                        # autoruns are too fast for different timestamps, so we need to add a microsecond to the timestamp >:/ FFS
                        if self.current_command and \
                            "operator" in self.current_command and \
                            "autoruns" == self.current_command['operator'] and \
                            "autoruns" == parsed_line['operator']:
                            parsed_line['timestamp'] = self.current_command['timestamp'] + timedelta(microseconds=1)
                            self.store_entry_to_db(parsed_line)
                            self.current_command = parsed_line
                            continue
                        
                        # store completed output if there is something to write
                        if self.current_output:
                            self.store_entry_to_db({'type': self.current_command['type'], 'timestamp': self.current_command['timestamp'], 'timezone': self.current_command["timezone"], 'content': self.current_output.strip()})    
                            
                        self.store_entry_to_db(parsed_line)
                        # Reset for the new command
                        self.current_command = parsed_line
                        self.current_output = ""
                        self.is_accumulating_output = False
                else:
                    # add the output to the current command
                    if self.is_accumulating_output:
                        self.current_output += line
                    # skip empty lines
                    elif re.match(r'^\s*$', line):
                        continue
                    # there are multiple outputs in one, so create the same output object again with new content
                    elif self.current_command:
                        # add a microsecond to the timestamp to avoid duplicates and keep the order
                        self.current_command['timestamp'] += timedelta(microseconds=1)
                        self.current_output += line
                    else:
                        if "watchlist.log" in self.filepath:
                            pass
                        else:
                            print(f"Could not parse {self.filepath} - {line}")
            # Last line of the file: Store the last command of the file and its output if applicable
            if self.current_output:
                self.store_entry_to_db({'type': self.current_command['type'], 'timestamp': self.current_command['timestamp'], 'timezone': self.current_command["timezone"], 'content': self.current_output.strip()})


    def parse_line(self, line: str) -> Dict:
        metadata_pattern = re.compile(r"(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[::badger authenticated from (?P<ips>.*)\]\[(?P<user>.*?)\]\[b-(?P<beacon_id>\d+?).*\]")
        watchlist_pattern = re.compile(r'(?P<timestamp>\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2} (?P<timezone>\w+))\s+\[Initial Access\]\s+b-(?P<beacon_id>\d+)\\\\[A-Z0-9]+\s+\((?P<user>.+?)\)\s+from\s+(?P<ips>.+?)\s+\[(?P<num1>\d+)->(?P<num2>\d+)\]')
        input_pattern = re.compile(r"^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[input\] (?P<operator>\w+) => (?P<command>.+)")
        output_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[sent \d+ bytes\]')
        output_end_pattern = re.compile(r'\+-+\+')
        upload_pattern = re.compile(r"(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \[UPLOAD\] (?P<content>Host: (?P<host>.*) \| File: (?P<file>.*) \| MD5: (?P<md5>[a-f0-9]{32}))")
        access_denied_pattern = re.compile(r"^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) (?P<content>Access denied \(.+\): \[(b-(?P<beacon_id>\d+))?.+\])")
        http_request_pattern = re.compile(r"(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+)) \n")
        http_log_pattern = re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (?P<timezone>\w+))\s+\[\+\] b-(?P<beacon_id>\d+)\s+(?P<content>.*: \[(?P<ips>.*)\])')
        
        metadata_match = metadata_pattern.match(line)
        watchlist_match = watchlist_pattern.match(line)
        input_match = input_pattern.match(line)
        output_match = output_pattern.match(line)
        output_end_pattern = output_end_pattern.match(line)
        upload_match = upload_pattern.match(line)
        access_denied_match = access_denied_pattern.match(line)
        http_request_match = http_request_pattern.match(line)
        http_log_match = http_log_pattern.match(line)
        
        if metadata_match:
            return {
                'type': 'metadata',
                'timestamp': self.parse_timestamp(metadata_match.group('timestamp')),
                'timezone': metadata_match.group('timezone'),
                'ip': extract_ips(metadata_match.group('ips'))[-1],
                'ip_ext': extract_ips(metadata_match.group('ips'))[0],
                'user': metadata_match.group('user').split("\\", 1)[1],
                'hostname': metadata_match.group('user').split("\\", 1)[0],
                'id': metadata_match.group('beacon_id')
            }
        elif watchlist_match:
            return {
                'type': 'metadata',
                'timestamp': self.parse_timestamp(watchlist_match.group('timestamp'), "%m-%d-%Y %H:%M:%S %Z"), # why?? different timestamp format
                'timezone': watchlist_match.group('timezone'),
                'ip': extract_ips(watchlist_match.group('ips'))[-1],
                'ip_ext': extract_ips(watchlist_match.group('ips'))[0],
                'user': watchlist_match.group('user').split("\\", 1)[1],
                'hostname': watchlist_match.group('user').split("\\", 1)[0],
                'id': watchlist_match.group('beacon_id')
            }
        elif input_match:
            return {
                'type': 'input',
                'timestamp': self.parse_timestamp(input_match.group('timestamp')),
                'timezone': input_match.group('timezone'),
                'operator': input_match.group('operator'),
                'content': input_match.group('command')
            }
        elif output_match:
            return {
                'type': 'output',
                'timestamp': self.parse_timestamp(output_match.group('timestamp')),
                'timezone': output_match.group('timezone'),
                # 'bytes': output_match.group('bytes'),
            }
        elif output_end_pattern:
            return {
                'type': 'output_end',
            }
        elif upload_match:
            return {
                'type': 'indicator',
                'timestamp': self.parse_timestamp(upload_match.group('timestamp')),
                'timezone': upload_match.group('timezone'),
                'content': upload_match.group('content')
                # 'host': upload_match.group('host'),
                # 'file': upload_match.group('file'),
                # 'md5': upload_match.group('md5'),
            }
        elif access_denied_match:
            return {
                'type': 'access_denied',
                'timestamp': self.parse_timestamp(access_denied_match.group('timestamp')),
                'timezone': access_denied_match.group('timezone'),
                'content': access_denied_match.group('content'),
                'parent_id': access_denied_match.group('beacon_id')
            }
        elif http_request_match:
            return {
                'type': 'http_request',
                'timestamp': self.parse_timestamp(http_request_match.group('timestamp')),
                'timezone': http_request_match.group('timezone'),
            }
        elif http_log_match:
            return {
                'type': 'http_log',
                'timestamp': self.parse_timestamp(http_log_match.group('timestamp')),
                'timezone': http_log_match.group('timezone'),
                'content': http_log_match.group('content'),
                'parent_id': http_log_match.group('beacon_id'),
            }
        return None
    

    def store_entry_to_db(self, entry_data: Dict):
        entry_type = EntryType[entry_data['type']]
        entry_data['parent_id'] = self.beacon_id if self.beacon_id != None else entry_data.get('parent_id', -1) # why?? upload has no beacon reference
        try:
            existing_entry = self.session.query(Entry).filter_by(
                timestamp=entry_data['timestamp'],
                timezone=entry_data['timezone'],
                type=entry_type,
                parent_id=entry_data['parent_id'],
                content=entry_data.get('content')
            ).one_or_none()

            if existing_entry is None:
                entry = Entry(**entry_data)
                self.session.add(entry)
                self.entries_added += 1
            else:
                # Update the existing entry
                existing_entry.ttp = entry_data.get('ttp')
                existing_entry.operator = entry_data.get('operator')
                existing_entry.content = entry_data.get('content')
                self.session.add(existing_entry)

            self.session.commit()
        except Exception as e:
            self.session.rollback()
            print(f"Failed to insert log entry: {e}")

    def store_beacon_to_db(self, metadata: Dict):
        metadata.pop('type', None)
        metadata['id'] = self.beacon_id if self.beacon_id else metadata['id']
        if not metadata['id']:
            raise ValueError("Beacon ID not found in metadata")
        
        try:
            existing_beacon = self.session.query(Beacon).filter_by(
                id=metadata['id']
            ).one_or_none()

            if existing_beacon is None:
                beacon = Beacon(**metadata)
                self.session.add(beacon)
            else:
                # Update the existing beacon via **metadata
                existing_beacon.timestamp = metadata['timestamp']
                existing_beacon.ip = metadata['ip']
                existing_beacon.ip_ext = metadata['ip_ext']
                existing_beacon.user = metadata['user']
                existing_beacon.hostname = metadata['hostname']
                # existing_beacon.process = metadata['process']
                # existing_beacon.pid = metadata['pid']
                # existing_beacon.os = metadata['os']
                # existing_beacon.version = metadata['version']
                # existing_beacon.build = metadata['build']
                # existing_beacon.arch = metadata['arch']
                self.session.add(existing_beacon)

            self.session.commit()
        except Exception as e:
            self.session.rollback()
            print(f"Failed to insert or update beacon: {e}")

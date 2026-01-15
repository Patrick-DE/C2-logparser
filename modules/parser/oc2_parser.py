import json
import os
import re
import threading
from datetime import datetime
from typing import Dict, Optional, Tuple

from pathlib import Path
import sys

from sqlalchemy import inspect
from sqlalchemy.orm import Session

from modules.sql.sqlite_func import init_db
from modules.sql.sqlite_model import Beacon, Entry, EntryType


class OC2LogParser:
    TIMESTAMP_REGEX = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+UTC)\s*(?P<payload>\{.*)",
        re.DOTALL,
    )

    def __init__(self, filepath: str, db_path: str, debug: bool = False):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        session_factory = init_db(db_path, debug)
        self.session: Session = session_factory()
        self.lock = threading.RLock()
        self.implant_uid_to_db_id: Dict[str, int] = {}
        # Track number of entries added to database
        self.entries_added = 0

    @classmethod
    def parse_beacon_log(cls, filepath: str, db_path: str, debug: bool = False) -> int:
        parser = cls(filepath, db_path, debug)
        parser.parse()
        return parser.entries_added

    @staticmethod
    def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
        if not timestamp_str:
            return None
        dt_str = (timestamp_str.replace("UTC", "")
            .replace("Z", "")
            .replace("T", " ")
            .strip()
        )
        try:
            if "." in dt_str:
                return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
            else:
                return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            print(f"Error parsing timestamp '{timestamp_str}': unsupported format.")
            return None

    def read_line(self, line: str, line_num: int) -> Optional[Tuple[datetime, Dict]]:
        match = self.TIMESTAMP_REGEX.match(line)
        if not match:
            print(f"Warning: Skipping line {line_num} due to format mismatch (timestamp/JSON) in file {self.filename}.")
            return None

        timestamp = self.parse_timestamp(match.group("timestamp"))
        if not timestamp:
            print(f"Warning: Skipping line {line_num} due to timestamp parsing error in file {self.filename}.")
            return None

        json_part = match.group("payload")
        try:
            log_data = json.loads(json_part)
        except json.JSONDecodeError as exc:
            snippet = json_part[:100]
            if len(json_part) > 100:
                snippet += "..."
            print(f"Warning: Skipping line {line_num} due to invalid JSON in file {self.filename}: {exc}: {snippet}")
            return None
        except Exception as exc:
            print(f"Error during initial parsing of line {line_num} in file {self.filename}: {exc}")
            return None

        return timestamp, log_data

    def parse(self) -> None:
        print(f"Starting parsing for file: {self.filename}")
        line_num = 0
        try:
            with open(self.filepath, "r", encoding="utf-8") as file:
                for raw_line in file:
                    line_num += 1
                    line = raw_line.strip()
                    if not line:
                        continue

                    parsed_line = self.read_line(line, line_num)
                    if not parsed_line:
                        continue

                    timestamp, log_data = parsed_line
                    self._process_event(line_num, timestamp, log_data)
        except FileNotFoundError:
            print(f"Error: File not found at {self.filepath}")
        except Exception as exc:
            print(f"An unexpected error occurred while reading {self.filepath}: {exc}")
        finally:
            self.close()
            # print(f"Finished parsing file: {self.filename}")

    def _process_event(
        self, line_num: int, timestamp: datetime, log_data: Dict
    ) -> None:
        event_type = log_data.get("event_type")
        implant_data = log_data.get("implant")
        task_data = log_data.get("task")

        db_beacon_id = self.get_beacon_db_id(implant_data, timestamp)

        if implant_data and db_beacon_id is None:
            uid = implant_data.get("uid")
            print(f"Warning: Could not get or create beacon for implant UID {uid} on line {line_num} in file {self.filename}. Skipping entry.")
            return

        if event_type in ("task_request", "task_response"):
            if not db_beacon_id:
                print(f"Warning: Cannot store task entry for event '{event_type}' on line {line_num} as implant DB ID is unknown in file {self.filename}.")
                return
            if not task_data or not isinstance(task_data, dict):
                print(f"Warning: Missing task_data for event '{event_type}' on line {line_num} in file {self.filename}.")
                return
            if "uid" not in task_data or "name" not in task_data:
                print(f"Warning: Task data missing 'uid' or 'name' on line {line_num} in file {self.filename}. Skipping task entry.")
                return
            self.store_task_entry_to_db(event_type, timestamp, db_beacon_id, task_data)
        elif event_type == "new_implant":
            return
        else:
            return

    def get_beacon_db_id(
        self, implant_data: Optional[Dict], timestamp: datetime
    ) -> Optional[int]:
        if not implant_data or not isinstance(implant_data, dict):
            return None

        implant_uid = implant_data.get("uid")
        if not implant_uid:
            print(f"Warning: Implant data missing 'uid' in file {self.filename}. Cannot associate entry.")
            return None

        db_beacon_id = self.implant_uid_to_db_id.get(implant_uid)
        if db_beacon_id:
            self.update_beacon_details(db_beacon_id, implant_data, timestamp)
            return db_beacon_id

        with self.lock:
            existing = (self.session.query(Beacon)
                .filter(Beacon.uid_str == implant_uid)
                .one_or_none()
            )
            if existing:
                self.implant_uid_to_db_id[implant_uid] = existing.id
                self.update_beacon_details(existing.id, implant_data, timestamp)
                return existing.id

            db_beacon_id = self.get_or_create_beacon(implant_data, timestamp)
            if db_beacon_id:
                self.implant_uid_to_db_id[implant_uid] = db_beacon_id
            return db_beacon_id

    def get_or_create_beacon(
        self, implant_data: Dict, timestamp: datetime
    ) -> Optional[int]:
        implant_uid = implant_data.get("uid")
        if not implant_uid:
            print("Error: get_or_create_beacon called with missing implant UID.")
            return None

        first_seen = self.parse_timestamp(implant_data.get("first_seen", "")) or timestamp

        beacon = Beacon(
            uid_str=implant_uid,
            timestamp=first_seen,
            timezone="UTC",
            hostname=implant_data.get("hostname"),
            user=implant_data.get("username"),
            ip=implant_data.get("ip"),
            ip_ext=implant_data.get("transport_ip"),
            process=implant_data.get("proc_name"),
            pid=implant_data.get("pid"),
            os=implant_data.get("os"),
            version=implant_data.get("version"),
            arch=str(implant_data.get("arch")) if implant_data.get("arch") is not None else None,
        )

        with self.lock:
            try:
                self.session.add(beacon)
                self.session.flush()
                db_id = beacon.id
                self.session.commit()
                print(f"Info: Created new Beacon DB record ID {db_id} for implant UID {implant_uid}")
                return db_id
            except Exception as exc:
                self.session.rollback()
                print(f"Failed to create Beacon record for implant {implant_uid}: {exc}")
                return None

    def update_beacon_details(
        self,
        db_beacon_id: int,
        implant_data: Dict,
        fallback_timestamp: Optional[datetime] = None,
    ) -> None:
        try:
            with self.lock:
                beacon = (self.session.query(Beacon)
                    .filter_by(id=db_beacon_id)
                    .one_or_none()
                )
                if not beacon:
                    return

                updated = False

                last_seen_raw = implant_data.get("last_seen")
                last_seen_dt = self.parse_timestamp(last_seen_raw) if last_seen_raw else fallback_timestamp
                if last_seen_dt and hasattr(beacon, "last_seen"):
                    if not beacon.last_seen or last_seen_dt > beacon.last_seen:
                        beacon.last_seen = last_seen_dt
                        updated = True

                checkin_count = implant_data.get("checkin_count")
                if (
                    checkin_count is not None
                    and hasattr(beacon, "checkin_count")
                    and (
                        beacon.checkin_count is None
                        or checkin_count > beacon.checkin_count
                    )
                ):
                    beacon.checkin_count = checkin_count
                    updated = True

                pid = implant_data.get("pid")
                if hasattr(beacon, "pid") and pid is not None and beacon.pid != pid:
                    beacon.pid = pid
                    updated = True

                if updated:
                    self.session.add(beacon)
                    self.session.commit()
        except Exception as exc:
            self.session.rollback()
            print(f"Failed to update details for Beacon ID {db_beacon_id}: {exc}")

    def store_task_entry_to_db(
        self,
        event_type: str,
        timestamp: datetime,
        db_beacon_id: int,
        task_data: Dict,
    ) -> None:
        operator = task_data.get("operator")
        task_uid = task_data.get("uid")
        task_name = task_data.get("name")
        arguments = task_data.get("arguments")
        response = task_data.get("response")

        if event_type == "task_request":
            entry_type = EntryType.input
            content_parts = [task_name] if task_name else []
            if arguments:
                if isinstance(arguments, str):
                    content_parts.append(arguments)
                else:
                    content_parts.append(json.dumps(arguments))
            content = " ".join(part for part in content_parts if part)
        elif event_type == "task_response":
            entry_type = EntryType.output
            if response is None:
                content = "[No Response Content]"
            elif isinstance(response, str):
                content = response
            else:
                content = json.dumps(response)
        else:
            return

        entry_data = {
            "timestamp": timestamp,
            "timezone": "UTC",
            "type": entry_type,
            "parent_id": db_beacon_id,
            "task_uid": task_uid,
            "operator": operator,
            "content": content.strip() if content else "",
            "ttp": None,
        }

        try:
            with self.lock:
                duplicate = (
                    self.session.query(Entry)
                    .filter(
                        Entry.timestamp == entry_data["timestamp"],
                        Entry.parent_id == entry_data["parent_id"],
                        Entry.type == entry_data["type"],
                        Entry.task_uid == entry_data["task_uid"],
                    )
                    .first()
                )
                if duplicate:
                    return

                db_entry = Entry(**entry_data)
                self.session.add(db_entry)
                self.session.commit()
                self.entries_added += 1
        except Exception as exc:
            self.session.rollback()
            print(f"Failed to insert Entry for task {task_uid} (Beacon ID {db_beacon_id}): {exc}")

    def close(self) -> None:
        if self.session:
            self.session.close()

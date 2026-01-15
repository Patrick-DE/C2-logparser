import os
import sys
import time
from typing import Dict, List

import sqlalchemy
from sqlalchemy.future import select
from sqlalchemy.future.engine import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import exc, update, delete, text, or_, and_, func

from modules.sql.sqlite_model import *
from modules.configuration import is_ip_excluded, get_config, AndCommand
from modules.utils import log

config = get_config()
SESSION = None

def init_db(db_path, debug):
    global SESSION
    try:
        tmp_path = os.path.dirname(db_path)
        if not os.path.isdir(tmp_path):
            os.mkdir(tmp_path)
        engine = create_engine("sqlite:///"+db_path,echo=debug)
    except Exception as ex:
        log(f"Please provide a valid DB path: {ex}", "e")
        sys.exit(-1)

    SESSION = sessionmaker(engine)
    try:
        Base.metadata.create_all(engine)
        return SESSION
    except Exception as ex:
        log(f"Please provide a valid DB path: {ex}", "e")
        sys.exit(-1)


# =========================
# =========GENERIC=========
# =========================
def get_element_by_id(cls, id):
    """
    Get row of type CLS (generic) with ID id
    """
    session = SESSION()
    record = None
    try:
        records = session.execute(select(cls).where(cls.id == id))
        results = records.scalars().first()
        return results
    except Exception as ex:
        log(f"get_element_by_id() Failed: {ex}", "e")
    finally:
        session.close()


def get_all_elements(cls):
    session = SESSION()
    rec =[]
    try:
        records = session.execute(select(cls))
        results = records.unique().scalars().fetchall()
        return results
    except Exception as ex:
        log(f"get_all_elements() Failed: {ex}", "e")
    finally:
        session.close()


def update_element(cls, **kwargs):
    session = SESSION()
    try:
        session.execute(
            update(cls).
            where(cls.id == kwargs["id"]).
            values(kwargs)
            )
        session.commit()
    except exc.IntegrityError:
        pass
    except Exception as ex:
        log(f"update_element() Failed: {ex}", "e")
    finally:
        session.close()

    return get_element_by_id(cls, kwargs["id"])


def delete_element(cls, id):
    session = SESSION()
    try:
        session.execute(delete(cls).where(cls.id == id))
        session.commit()
    except Exception as ex:
        log(f"delete_element() Failed: {ex}", "e")
    finally:
        session.close()


def get_element_by_values(cls, **kwargs):
    """
    Get one element of type CLS (generic) where values match
    """
    session = SESSION()
    bindTo = []
    try:
        #remove externalIP because beacons can connect to beacons ..
        kwargs.pop('ip_ext', None)

        for key, value in kwargs.items():
            bindTo.append(f"{ str(key) }=:{ str(key) }")

        qry = str(" and ".join(bindTo))
        query = f"SELECT * FROM {cls.__tablename__} WHERE {qry}"
        records = session.execute(text(query).bindparams(**kwargs))
        result = records.scalar()
        return result
    except Exception as ex:
        log(f"get_element_by_values() Failed: {ex}", "e")
    finally:
        session.close()


def create_element(cls, **kwargs):
    elem = get_element_by_values(cls, **kwargs)
    if elem:
        return elem

    session = SESSION()
    try:
        # if beacon is unknown drop id so it auto generates one
        if "id" in kwargs and kwargs["id"] == '':
            kwargs.pop("id")

        record = cls()
        for k, v in kwargs.items():
            setattr(record, k, v)

        session.add(record)
        session.commit()
        return record.id
    except exc.IntegrityError:
        elem = get_element_by_id(cls, kwargs["id"])
        return elem.id
    except Exception as ex:
        log(f"create_element({cls}) Failed: {ex}", "e")
    except sqlalchemy.sqlite3.OperationalError as ex:
        log(f"create_element({cls}) Failed: Database busy! Retrying..{ex}", "w")
        time.sleep(1)
        create_element(cls, **kwargs)
    finally:
        session.close()

# =========================
# =========BEACONS=========
# =========================
def get_last_entry_of_beacon(id):
    session = SESSION()
    record = None
    try:
        records: Entry = session.execute(select(Entry).where(Entry.parent_id == id ).order_by(Entry.timestamp.desc()))
        return records.scalars().first()
    except Exception as ex:
        log(f"get_last_entry_of_beacon() Failed: {ex}", "e")
    finally:
        session.close()


def get_first_metadata_entry_of_beacon(id):
    session = SESSION()
    try:
        records: Entry = session.execute(select(Entry).where(Entry.parent_id == id ).where(Entry.type == EntryType.metadata))
        result = records.scalars().first()
        return result
    except Exception as ex:
        log(f"get_first_metadata_entry_of_beacon() Failed: {ex}", "e")
    finally:
        session.close()


def get_all_incomplete_beacons():
    session = SESSION()
    try:
        records: Entry = session.execute(
            select(Beacon).filter(
                or_(
                    Beacon.hostname == None,
                    Beacon.exited == None
                )
            )
        )
        result = records.unique().scalars().fetchall()
        return result
    except Exception as ex:
        log(f"get_all_incomplete_beacons() Failed: {ex}", "e")
    finally:
        session.close()


def get_all_valid_beacons() -> List[Beacon]:
    session = SESSION()
    try:
        records: Beacon = session.execute(
            select(Beacon).filter(
                and_(
                    Beacon.hostname != None,
                    Beacon.joined != None
                )
            )
        )
        result = records.unique().scalars().fetchall()
        return result
    except Exception as ex:
        log(f"get_all_complete_beacons() Failed: {ex}", "e")
    finally:
        session.close()


def get_last_beacon_entry_time(beacon_id: int):
    session = SESSION()
    try:
        # Query to fetch the latest timestamp of an entry for a specific beacon
        last_entry_time = session.query(func.max(Entry.timestamp)).filter(Entry.parent_id == beacon_id).scalar()
        return last_entry_time
    except Exception as e:
        print(f"Failed to fetch last entry time for beacon {beacon_id}: {e}")
        return None
    finally:
        session.close()
# =========================
# ==========ENTRY==========
# =========================
def get_entry_by_param(timestamp, timezone, type, content):
    session = SESSION()
    record = None
    try:
        records: Entry = session.execute(
            select(Entry).
            where(Entry.timestamp == timestamp).
            where(Entry.timezone == timezone).
            where(Entry.type == type)
            )
        record = records.scalars().first()
    except Exception as ex:
        log(f"get_entry_by_param() Failed: {ex}", "e")
    finally:
        session.close()

    return excel_save(redact(record.content))


def get_all_entries_filtered(filter: EntryType, redacting: bool=True) -> List[Entry]:
    session = SESSION()
    try:
        records: Entry = session.execute(select(Entry).where(Entry.type == filter).order_by(Entry.timestamp.asc()))
        results = records.unique().scalars().fetchall()
        # reduct will be done at .to_row() level
        return results
    except Exception as ex:
        log(f"get_all_entries_filtered() Failed: {ex}", "e")
    finally:
        session.close()


def get_all_entries_filtered_containing(filter: EntryType, cont: String) -> List[Entry]:
    """
    Get all entrytype called filter which contains sttring called cont
    """
    session = SESSION()
    try:
        records: Entry = session.execute(
            select(Entry).filter(
                and_(
                    Entry.type == filter,
                    Entry.content.contains(cont)
                )
            ).order_by(Entry.timestamp.asc())
        )
        results = records.unique().scalars().fetchall()
        # reduct will be done at .to_row() level
        return results
    except Exception as ex:
        log(f"get_all_entries_filtered_containing() Failed: {ex}", "e")
    finally:
        session.close()


def get_upload_entries():
    """
    Get one element of type CLS (generic) where values match
    """
    session = SESSION()
    try:
        records = session.execute(select(Entry).filter(
            or_(
                Entry.content.contains('Uploading beaconloader:'),
                Entry.content.contains('Uploading payload file:'),
                Entry.content.contains('Tasked beacon to upload'),
                Entry.type == EntryType.indicator
            )
        ))
        results = records.unique().scalars().fetchall()
        # reduct will be done at .to_row() level
        return results
    except Exception as ex:
        log(f"get_element_by_values() Failed: {ex}", "e")
    finally:
        session.close()
        
        

# =========================
# =========CLEANUP=========
# =========================


def test_remove_clutter():
    session = SESSION()
    try:
        records = session.execute(select(Entry).filter(
            or_(
                Entry.content.contains('clear'),
                Entry.content.contains('jobs'),
                Entry.content.contains('jobkill'),
                Entry.content.contains('cancel'),  
            )).order_by(Entry.timestamp.asc()))

        result = records.unique().scalars().fetchall()
        return result
    except Exception as ex:
        log(f"get_all_entries_filtered() Failed: {ex}", "e")
    finally:
        session.close()

def build_filter_conditions(filters: List[str]):
    """Build SQLAlchemy filter conditions from list of strings"""
    or_conditions = []
    try:
        for filter_item in filters:
            if isinstance(filter_item, dict):
                if "_and" in filter_item:
                    and_conditions = [Entry.content.contains(part) for part in filter_item["_and"]]
                    or_conditions.append(and_(*and_conditions))
                if "_regex" in filter_item:
                    regex_conditions = [Entry.content.op('REGEXP')(part) for part in filter_item["_regex"]]
                    for regex in regex_conditions:
                        or_conditions.append(regex)
            else:
                or_conditions.append(Entry.content.contains(filter_item))
    except Exception as e:
        log(f"Please format your filter correctly in the config.yml: {e}", "e")

    return or_conditions

def remove_clutter():
    """This function removes the following entries from the DB:
    - keylogger output
    - sleep commands issues by the operator
    - BeaconBot responses
    - Screenshot output
    https://docs.sqlalchemy.org/en/14/core/expression_api.html"""
    config = get_config()
    session = SESSION()
    try:
        # Get filters from config
        filters = config.exclusions.commands
        conditions = build_filter_conditions(filters)
        
        entries = session.query(Entry).filter(or_(*conditions))
        count = entries.count()
        entries.delete(synchronize_session=False)
        session.commit()
        log(f"Removed {count} clutter entries")
        
    except Exception as ex:
        log(f"remove_clutter() Failed: {ex}", "e")
        session.rollback()
    finally:
        session.close()

def remove_via_ip(excluded_ranges, public_ip=False):
    """Remove beacons and entries for ip_ext in excluded_ranges:
    https://docs.sqlalchemy.org/en/14/core/expression_api.html"""
    session = SESSION()
    try:
        if not excluded_ranges:
            return

        # Get all beacons
        beacons = session.query(Beacon).all()
        
        # Filter beacons with excluded IPs
        beacon_ids = []
        for beacon in beacons:
            if public_ip:
                if beacon.ip_ext and is_ip_excluded(beacon.ip_ext, excluded_ranges):
                    beacon_ids.append(beacon.id)
            elif not public_ip:
                if beacon.ip and is_ip_excluded(beacon.ip, excluded_ranges):
                    beacon_ids.append(beacon.id)
            else:
                log(f"remove_via_ip() Failed: Invalid public_ip value: {public_ip}", "e")
                return

        if beacon_ids:
            # Remove related entries first
            session.query(Entry).filter(
                Entry.parent_id.in_(beacon_ids)
            ).delete(synchronize_session=False)

            # Remove beacons
            session.query(Beacon).filter(
                Beacon.id.in_(beacon_ids)
            ).delete(synchronize_session=False)

            session.commit()
            
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def remove_beacons_via_hostname(excluded_hostnames):
    """Remove beacons and entries where hostname matches excluded hostnames in config"""
    session = SESSION()
    try:
        if not excluded_hostnames:
            return

        # Get all beacons
        beacons = session.query(Beacon).all()
        
        # Filter beacons with excluded hostnames (contains match)
        beacon_ids = [
            beacon.id for beacon in beacons 
            if beacon.hostname and any(host.lower() in beacon.hostname.lower() for host in excluded_hostnames)
        ]

        if beacon_ids:
            # Remove related entries first
            session.query(Entry).filter(
                Entry.parent_id.in_(beacon_ids)
            ).delete(synchronize_session=False)

            # Remove beacons
            session.query(Beacon).filter(
                Beacon.id.in_(beacon_ids)
            ).delete(synchronize_session=False)

            session.commit()
            
    except Exception as e:
        session.rollback()
        log(f"remove_via_hostname() Failed: {e}", "e")
        raise e
    finally:
        session.close()


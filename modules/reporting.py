from modules.sql.sqlite_func import *
from modules.utils import *
from modules.ttp import *

def sort_on_timestamp(elem: Entry):
    return elem.timestamp

def sort_on_joined(elem: Beacon):
    return elem.joined

def report_input_task(output):
    # input report
    entries = get_all_entries_filtered(filter=EntryType.input)
    entries = entries + get_all_entries_filtered(filter=EntryType.task)
    entries.sort(key=sort_on_timestamp)
    rows = []
    for entry in entries:
        rows.append(entry.to_row())
    header = ["Date", "Time", "Hostname", "Command", "User", "IP"]
    write_to_csv(os.path.join(output,"activity-report.csv"), header, rows)

def report_dl_ul(output):
    """
    get download and upload report
    """
    entries = get_all_entries_filtered_containing(filter=EntryType.task, cont="Tasked beacon to download")
    entries = entries + get_upload_entries()
    entries.sort(key=sort_on_timestamp)
    rows = []
    for entry in entries:
        rows.append(entry.to_row(redacting=False))
    header = ["Date", "Time", "Hostname", "File", "User", "IP"]
    write_to_csv(os.path.join(output,"dl-ul-report.csv"), header, rows)

def report_all_beacons_spawned(output):
    beacons = get_all_valid_beacons()
    beacons.sort(key=sort_on_joined)
    rows = []
    for beacon in beacons:
        rows.append(beacon.to_row())
    header = ["Hostname", "IP", "Internet via IP", "User", "Process", "Process ID", "Joined", "Exited"]
    write_to_csv(os.path.join(output,"beacon-report.csv"), header, rows)

def report_all_indicators(output):
    """
    get download and upload report
    """
    entries = get_all_entries_filtered(filter=EntryType.indicator)
    entries.sort(key=sort_on_timestamp)
    rows = []
    for entry in entries:
        rows.append(entry.to_row(redacting=False))
    header = ["Date", "Time", "Hostname", "File", "User", "IP"]
    write_to_csv(os.path.join(output,"ioc-report.csv"), header, rows)



from os import path
import argparse
from concurrent import futures

from modules.reporting import *
from modules.parser.cs_parser import *
from modules.configuration import get_config, load_config, config
from modules.utils import get_all_files
from modules.parser.cs_parser import CSLogParser
from modules.parser.br_parser import BRLogParser
from modules.parser.oc2_parser import OC2LogParser


"""
TODO
Map to every task an output
Detect based on the next output if the command was successfull or not
"""


def run(args):
    global config
    start = time.time()

    if args.config:
        load_config(args.config)

    config = get_config()
    if config is None:
        log("No configuration loaded!", LogType.ERROR)
        exit(-1)

    parser, file_extension = None, None
    if args.parser == 'cs':
        parser = CSLogParser
        file_extension = ".log"
    elif args.parser == 'br':
        parser = BRLogParser
        file_extension = ".log"
    elif args.parser == 'oc2':
        parser = OC2LogParser
        file_extension = ".json"

    init_db(args.database, args.verbose)

    if args.logs:
        log_files = get_all_files(args.logs, file_extension)
        total_entries_added = 0
        
        with futures.ThreadPoolExecutor(max_workers=args.worker) as executor:
            file_to_future = {executor.submit(parser.parse_beacon_log, file, args.database): file for file in log_files}
            
            for idx, future in enumerate(futures.as_completed(file_to_future)):
                printProgressBar(idx, len(file_to_future), "Process logs")
                try:
                    entries_added = future.result()
                    total_entries_added += entries_added if entries_added else 0
                except Exception as e:
                    log(f"Error processing {file_to_future[future]}: {e}", LogType.ERROR)
        
        # Inform user if no entries were added from the entire ingestion
        if total_entries_added == 0:
            log(f"\nWarning: No elements were added to the database from the ingested files.", LogType.WARNING)


    if args.minimize:
        remove_clutter()
        remove_via_ip(config.exclusions.external, True)
        remove_via_ip(config.exclusions.internal, False)
        remove_beacons_via_hostname(config.exclusions.hostnames)

    if args.report:
        report_input_task(args.output)
        report_dl_ul(args.output)
        report_all_beacons_spawned(args.output)
        report_all_indicators(args.output)
        report_tiber(args.output)

    print(time.time() - start)


class ValidatePath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        npath = path.abspath(values.strip())
        if not npath:
            return

        if not path.isdir(npath):
            os.mkdir(npath)
            #log(f"Please choose a valid path for {self.dest}!", "e")
            #exit(-1)

        setattr(namespace, self.dest, npath)

class ValidateFile(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        npath = path.abspath(values.strip())
        if not npath:
            return

        if not path.isfile(npath):
            log(f"Please choose a valid file for {self.dest}!", "e")
            exit(-1)

        setattr(namespace, self.dest, npath)

def strip_input(choice) -> str:
    return choice.strip()

if __name__ == "__main__":
    curr_path = path.dirname(path.abspath(__file__))

    parser = argparse.ArgumentParser(description='Parse CobaltStrike logs and store them in a DB to create reports')
    parser.add_argument('-w', '--worker', type=int, default=10, help='Set amount of workers: default=10')
    parser.add_argument('-v', '--verbose', action='store_true', help='Activate debugging')
    parser.add_argument('-l', '--logs', action=ValidatePath, help='Directory path containing the CS logs')
    parser.add_argument('-m', '--minimize', action='store_true', help='Remove unnecessary data: keyloggs,beaconbot,sleep,exit,clear')
    parser.add_argument('-p', '--path', action=ValidatePath, help='Database and reports path: default=<currentpath>')
    parser.add_argument('-r', '--report', action='store_true', help='Generate reports from database')
    parser.add_argument('-c', '--config', required=True, action=ValidateFile, help='A file with one IP-Range per line which should be ignored')
    parser.add_argument('-x', '--parser', type=strip_input, default='cs', choices=['cs', 'br', 'oc2'], help='Choose the parser: default=cs')
    
    try:
        args = parser.parse_args()
    except SystemExit:
        parser.print_help(sys.stderr)
        exit()

    # either path and parser or database
    if (not args.logs and not args.path):
        parser.print_help(sys.stderr)
        log("-----Examples-----", LogType.WARNING)
        log("Ingest only:        python3 gimmelogs.py -l <LogDir> -c config.yml", LogType.WARNING)
        log("Ingest + reports:   python3 gimmelogs.py -l <LogDir> -c config.yml -r", LogType.WARNING)
        log("Full:               python3 gimmelogs.py -l <LogDir> -c config.yml -m -r -p <OutputDir> -w 15", LogType.WARNING)
        log("Reports only:       python3 gimmelogs.py -p <DBDir> -c config.yml -r", LogType.WARNING)
        exit()

    if args.logs and not args.path:
        args.path = args.logs
        
    args.database = os.path.join(args.path, 'log.db')
    args.output = os.path.join(args.path, 'reports')
    if not path.isdir(args.output):
        os.mkdir(args.output)
    """TODO
    Reports:
    input -> done
    input - output
    file upload - download -> need to change type of upload tasks to upload
    """
    if args.verbose:
        args.worker = 1

    run(args)

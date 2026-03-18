# C2 Log-Parser
## Support for Cobalt Strike, Brute Ratel and Outflank C2 (OC2)

Parses C2 log files, stores them in a SQLite database, and generates CSV reports for red team engagements.

## Setup
```bash
python3 -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

pip install -r requirements.txt
```

## Usage

The tool operates in three independent phases that can be combined:

| Phase | Flag | Description |
|-------|------|-------------|
| **Ingest** | `-i <LogDir>` | Parse log files and store them in a SQLite DB (requires `-x`) |
| **Minimize** | `-m` | Remove clutter and exclude beacons via config |
| **Report** | `-r` | Generate CSV reports from the database |

### Quick usage
```bash
python3 gimmelogs.py -x <parser> -i <LogDir> -c config.yml
```

### Full usage
```bash
python3 gimmelogs.py -x <parser> -i <LogDir> -c config.yml -m -r -p <OutputDir> -w 15
```

### Examples
```bash
# Ingest only
python3 gimmelogs.py -x cs -i ./logs -c config.yml

# Report from existing DB
python3 gimmelogs.py -r -p ./results -c config.yml -m

# Minimize existing DB
python3 gimmelogs.py -p ./results -c config.yml -m

# Full pipeline: ingest, minimize, report
python3 gimmelogs.py -x cs -i ./logs -c config.yml -m -r -p ./results -w 15
```

## Commands
```
Parse C2 logs and store them in a DB to create reports

required arguments:
  -c CONFIG, --config CONFIG    A config file, see config_template.yml

optional arguments:
  -h, --help                    Show this help message and exit
  -x PARSER, --parser PARSER    Select parser: "cs", "br" or "oc2" (required with -i)
  -w WORKER, --worker WORKER    Set amount of workers (default: 10, set to 1 with -v)
  -v, --verbose                 Activate debugging (forces single worker)
  -i INGEST, --ingest INGEST    Directory path containing the C2 logs (requires -x)
  -p PATH, --path PATH          Output path for the reports and DB (default: <IngestDir>)
  -m, --minimize                Remove clutter and apply exclusions from config
  -r, --report                  Generate CSV reports from the database
```

## Configuration

See `config_template.yml` for a full example. The config file controls:

### Exclusions (`-m`)
| Type | Matching | Description |
|------|----------|-------------|
| `external` | CIDR range | Exclude beacons by external IP |
| `internal` | CIDR range | Exclude beacons by internal IP |
| `hostnames` | Regex (case-insensitive) | Exclude beacons by hostname |
| `users` | Regex (case-insensitive) | Exclude beacons by user |
| `commands` | Contains / `_and` / `_regex` | Remove log entries matching patterns |

### Redactions
Sensitive data (passwords, hashes, tokens) is automatically redacted in reports based on configurable regex patterns and replacement strings.

## Reporting (`-r`)

The following CSV reports are generated into `<OutputDir>/reports/`:

| Report | Description |
|--------|-------------|
| `activity-report.csv` | All operator input and task entries |
| `dl-ul-report.csv` | File download and upload activity |
| `beacon-report.csv` | All valid beacons with metadata (hostname, IP, user, process, join/exit times) |
| `ioc-report.csv` | Indicators of compromise (file hashes, filenames) |
| `tiber-report.csv` | TIBER-EU formatted report with auto-mapped MITRE ATT&CK TTPs (requires `ttps.csv`) |

## Remarks
* Only beacons with input or tasks are listed, focusing the report on actual operator actions. Beacons spawned via persistence that are never interacted with will be ignored.
* Beacons without associated IDs (e.g. from broken `.cna` scripts) will be ignored.
* The TIBER report uses `ttps.csv` to auto-map commands to MITRE ATT&CK techniques.

## Todos
- [x] Make it work 😂
- [x] Linux support
- [x] Add support for OC2
- [ ] Create cleaner download / upload report

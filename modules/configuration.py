from dataclasses import dataclass
from enum import Enum
from typing import List, Dict
import yaml
import ipaddress

@dataclass
class Flags:
    case_insensitive: bool = True
    replacement: str = r"\1[REDACTED]"

@dataclass
class Pattern:
    pattern: str
    description: str

@dataclass
class Redactions:
    patterns: Dict[str, Pattern]
    flags: Flags

@dataclass
class AndCommand:
    _and: List[str]

@dataclass
class RegexCommand:
    _regex: List[str]

@dataclass
class Exclusions:
    internal: List[str]
    external: List[str]
    hostnames: List[str]
    users: List[str]
    commands: List[str|AndCommand|RegexCommand]

@dataclass
class Config:
    exclusions: Exclusions
    redactions: Redactions

# Initialize the global config with empty placeholders
config: Config = None


def load_config(filename: str) -> Config:
    """Load and process configuration from YAML file"""
    global config
    with open(filename) as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"[!] Failed to load configuration: {e}")
            config = None
            return
            
    config = Config(
        exclusions=Exclusions(**data['exclusions']),
        redactions=Redactions(
            patterns={k: Pattern(**v) for k, v in data['redactions']['patterns'].items()},
            flags=Flags(**data['redactions']['flags'])
        )
    )
    return config


def reload_config(filename: str) -> Config:
    """Reload configuration from file"""
    return load_config(filename)

def get_config() -> Config:
    """Get the current configuration"""
    return config

def is_ip_excluded(ip: str, excluded_ranges: List[str]) -> bool:
    """
    Check if IP is in any excluded range
    Args:
        ip: String IP address to check
        excluded_ranges: List of CIDR ranges as strings
    Returns:
        bool: True if IP is in any excluded range
    """
    # if SMB beacons are used, we dont have an IP
    if "beacon_" in ip: return False
    try:
        for range in excluded_ranges:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(range):
                return True
        return False
    except ValueError as ex:
        print("[!] Invalid IP:" + ip + " : " + ex.strerror)
        return False
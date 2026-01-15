from os import path
import string
from typing import Dict, List
from modules.sql.sqlite_model import *
from modules.sql.sqlite_func import *
from modules.utils import log, write_to_csv

def sort_on_timestamp(elem: Entry):
    return elem.timestamp

def sort_on_joined(elem: Beacon):
    return elem.joined
    
class TTPSearcher():
    path = "ttps.csv"
    seperator = ';'
    ready = False
    ttps :List[List] = []

    def __init__(self):
        self.ready = self.verify_ttpfile()
        if self.ready:
            self.read_ttps()
            self.ttps.sort(key=lambda x: len(x[0]), reverse=True) 


    def add_ttp(self, tiber :Dict) -> Dict:
        for arr in self.ttps:
            if len(arr) != 6:
                if '"\n' != arr[0]:
                    log(f"The ttp entry (" + ";".join(arr) + ") is not correct!")
                return tiber
            try:
                if arr[0].lower() in tiber["Operational Guidance"].lower():
                    tiber["Phase"] = arr[1]
                    tiber["Tactic"] = arr[2]
                    tiber["Technique ID"]  = arr[3]
                    tiber["Technique Name"] = arr[4]
                    tiber["Goal"] = arr[5]
                    return tiber              
            except Exception as e:
                log(f"Error while adding TTP from ttp.csv: {e}", "e")  

        return tiber

    def read_ttps(self):
        a_file = open(self.path)
        for line in a_file:
            line = line.strip()
            if line.startswith("#") or not line:
                continue

            arr = [field.strip() for field in line.split(self.seperator)]
            self.ttps.append(arr)
        
    def verify_path(self):
        self.path = path.abspath(os.path.dirname(self.path))
        if not self.path:
            log(f"Please choose a valid path for the TTP file: {self.path}!", "e")
            exit(-1)
        
    def verify_ttpfile(self):
        self.path = path.abspath(self.path.strip())
        if not path.isfile(self.path):
            log(f"The TTP file could not be found: {self.path}!", "e")
            return False
        return True

    

pre = [
# ["","Resource Development","T1583.001"," Acquire Infrastructure:  Domains","N/A","Registration of <DOMAIN> for Scenario <X>","Obtain domain for phishing","Success"],
# ["","Resource Development","T1585.001","Establish Accounts: Social Media Accounts","N/A","The LinkedIn persona <PERSONA> sent connection requests to a number of employees","Create a trust relationship","Only 2 people accepted"],
# ["","Resource Development","T1328"," Acquire Infrastructure:  Domains","N/A","Registration of <DOMAIN> for C2","Obtain domain for phishing","Not used"],
# ["","Resource Development","T1328"," Acquire Infrastructure:  Domains","N/A","Registration of <DOMAIN for login portal spoofing","Obtain domain for phishing","Success"],
# ["","Resource Development","T1328"," Acquire Infrastructure:  Domains","N/A","Registration of <DOMAIN to use as mail sender","Obtain domain for phishing","Success"],
# ["","Command And Control","T1090.004","Proxy: Domain Fronting","N/A","The command and control channel makes use of domain fronting via <DOMAIN> => static ip of x.x.x.x","Evade proxy defenses using domain fronting","Success"],
# ["","Command And Control","T1104","Multi-Stage Channels","N/A","The DLL retrieves  the beacon exe as a second stage to inject into svchost. The beacon is hosted via domain fronting on download.visualstudio.microsoft.com -> vstudio.azureedge.net => static ip of x.x.x.x","Evade defenses by loading the payload in memory as second stage","Success"],
# ["","Defense Evasion","T1027","Obfuscated Files or Information","N/A","The VBA payload was obfuscated to evade detection","Defense evasion with obfuscated payloads","Success"],
# ["","Defense Evasion","T1027","Obfuscated Files or Information","N/A","The VBA code itself was obfuscated, as was the DLL embedded inside the VBA code","Defense evasion with obfuscated payloads","Success"],
# ["","Defense Evasion","T1480.001","Execution Guardrails: Environmental Keying","N/A","The VBA payload would only run on domain-joined targets","Defense evasion using limted execution","Success"],
# ["","Defense Evasion","T1112","Modify Registry","N/A","Registry key written to perform COM hijack: Computer\\HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\<CLSID>","Perform COM hijack for persistance","Success"],
# ["","Execution","T1059.005","Command and Scripting Interpreter: Visual Basic","N/A","Office document (.doc) containing VBA code to perform the COM hijack with embedded DLL.","Evade detection by delaying payload execution with the COM hjiack","Success"]
]
def report_tiber(output):
    ttp = TTPSearcher()
    if not ttp.ready:
        return
        
    entries = get_all_entries_filtered(filter=EntryType.input)
    entries = entries + get_all_entries_filtered_containing(filter=EntryType.task, cont="Tasked beacon to")
    entries.sort(key=sort_on_timestamp)
    rows = pre
    
    tiber = None
    for entry in entries:
        tiber = {"Phase":"", "Tactic":"", "Technique ID":"", "Technique Name":"", "Executed on":"", "Operational Guidance":"", "Goal":"", "Result":"", "Thread Actor":"", "Related Findings(s)":"", "Date":"", "Time":""}
        tiber["Executed on"] = entry.parent.hostname if entry.parent.hostname else "N/A"
        tiber["Date"] = entry.timestamp.strftime("%d/%m/%Y")
        tiber["Time"] = entry.timestamp.strftime("%H:%M:%S")
        tiber["Operational Guidance"] = excel_save(redact(entry.content))
        tiber = ttp.add_ttp(tiber)     
        rows.append(tiber.values())

    if tiber:
        write_to_csv(output+"\\tiber-report.csv", tiber.keys(), rows)

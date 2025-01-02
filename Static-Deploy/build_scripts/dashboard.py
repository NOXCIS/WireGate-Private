import random, shutil, sqlite3, configparser
import bcrypt, psutil, pyotp, hashlib, secrets
import os, io, time, subprocess, uuid, threading
import tempfile, py7zr
import ipaddress
import json
import re
import logging


import waitress 



from logging.handlers import RotatingFileHandler
from time import strftime
from datetime import datetime, timedelta
from typing import Any, List
from flask import Flask, request, render_template, make_response, session, g, jsonify, send_file
from json import JSONEncoder
from flask_cors import CORS
from icmplib import ping, traceroute
from flask.json.provider import DefaultJSONProvider
from werkzeug.utils import secure_filename
from Utilities import (
    RegexMatch, GetRemoteEndpoint, StringToBoolean, 
    ValidateIPAddressesWithRange, ValidateIPAddresses, ValidateDNSAddress,
    GenerateWireguardPublicKey, GenerateWireguardPrivateKey
)





#Import Enviorment
DASHBOARD_VERSION = 'jiaotu'
DASHBOARD_MODE = None
CONFIGURATION_PATH = os.getenv('CONFIGURATION_PATH', '.')
DB_PATH = os.path.join(CONFIGURATION_PATH, 'db')
if not os.path.isdir(DB_PATH):
    os.mkdir(DB_PATH)
DASHBOARD_CONF = os.path.join(CONFIGURATION_PATH, 'db', 'wg-dashboard.ini')
WG_CONF_PATH = None
UPDATE = None


# Folder to save uploaded files
UPLOAD_FOLDER = os.path.abspath(
    os.path.join(os.path.dirname(__file__), 'Downloads')
)

app = Flask("WGDashboard", template_folder=os.path.abspath("./static/app/dist"))
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 5206928
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
app.secret_key = secrets.token_urlsafe(420)







# App config


wgd_config_path = os.environ.get('WGD_CONF_PATH') or "/etc/wireguard"
wgd_welcome = os.environ.get('WGD_WELCOME_SESSION') or "true"
wgd_app_port = os.environ.get('WGD_REMOTE_ENDPOINT_PORT') or "10086"
wgd_auth_req = os.environ.get('WGD_AUTH_REQ') or "true"
wgd_user = os.environ.get('WGD_USER') or "admin"
wgd_pass = os.environ.get('WGD_PASS') or "admin"
wgd_global_dns = os.environ.get('WGD_DNS') or "1.1.1.1"
wgd_peer_endpoint_allowed_ip = os.environ.get('WGD_PEER_ENDPOINT_ALLOWED_IP') or "0.0.0.0/0, ::/0"
wgd_keep_alive = os.environ.get('WGD_KEEP_ALIVE') or "21"
wgd_mtu = os.environ.get('WGD_MTU') or "1420"





class ModelEncoder(JSONEncoder):
    def default(self, o: Any) -> Any:
        if hasattr(o, 'toJson'):
            return o.toJson()
        else:
            return super(ModelEncoder, self).default(o)

class CustomJsonEncoder(DefaultJSONProvider):
    def __init__(self, app):
        super().__init__(app)

    def default(self, o):
        if (isinstance(o, Configuration)
                or isinstance(o, Peer)
                or isinstance(o, PeerJob)
                or isinstance(o, Log)
                or isinstance(o, DashboardAPIKey)
                or isinstance(o, PeerShareLink)):
            return o.toJson()
        return super().default(self, o)
app.json = CustomJsonEncoder(app)

'''
Response Object
'''
def ResponseObject(status=True, message=None, data=None) -> Flask.response_class:
    response = Flask.make_response(app, {
        "status": status,
        "message": message,
        "data": data
    })
    response.content_type = "application/json"
    return response

def get_backup_paths(config_name: str, backup_timestamp: str = None) -> dict:
    """
    Get organized backup file paths for a configuration
    Args:
        config_name: Name of the WireGuard configuration
        backup_timestamp: Optional timestamp for specific backup
    Returns:
        Dictionary containing backup paths
    """
    # Get base backup directory
    backup_dir = os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], 'WGDashboard_Backup')
    
    # Create config-specific directory
    config_backup_dir = os.path.join(backup_dir, config_name)
    os.makedirs(config_backup_dir, exist_ok=True)

    if backup_timestamp:
        return {
            'base_dir': backup_dir,
            'config_dir': config_backup_dir,
            'conf_file': os.path.join(config_backup_dir, f'{config_name}_{backup_timestamp}.conf'),
            'sql_file': os.path.join(config_backup_dir, f'{config_name}_{backup_timestamp}.sql'),
            'iptables_file': os.path.join(config_backup_dir, f'{config_name}_{backup_timestamp}_iptables.json')
        }
    return {
        'base_dir': backup_dir,
        'config_dir': config_backup_dir
    }

def _strToBool(value: str) -> bool:
        return value.lower() in ("yes", "true", "t", "1", 1)

"""
Log Class
"""
class Log:
    def __init__(self, LogID: str, JobID: str, LogDate: str, Status: str, Message: str):
        self.LogID = LogID
        self.JobID = JobID
        self.LogDate = LogDate
        self.Status = Status
        self.Message = Message
    
    def toJson(self):
        return {
            "LogID": self.LogID,
            "JobID": self.JobID,
            "LogDate": self.LogDate,
            "Status": self.Status,
            "Message": self.Message
        }

    def __dict__(self):
        return self.toJson()

"""
Dashboard Logger Class
"""
class DashboardLogger:
    def __init__(self):
        self.loggerdb = sqlite3.connect(os.path.join(CONFIGURATION_PATH, 'db', 'wgdashboard_log.db'),
                                        check_same_thread=False)
        self.loggerdb.row_factory = sqlite3.Row
        self.__createLogDatabase()
        self.log(Message="WGDashboard started")
    def __createLogDatabase(self):
        with self.loggerdb:
            loggerdbCursor = self.loggerdb.cursor()
            existingTable = loggerdbCursor.execute("SELECT name from sqlite_master where type='table'").fetchall()
            existingTable = [t['name'] for t in existingTable]
            if "DashboardLog" not in existingTable:
                loggerdbCursor.execute(
                    "CREATE TABLE DashboardLog (LogID VARCHAR NOT NULL, LogDate DATETIME DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now', 'localtime')), URL VARCHAR, IP VARCHAR, Status VARCHAR, Message VARCHAR, PRIMARY KEY (LogID))")
            if self.loggerdb.in_transaction:
                self.loggerdb.commit()
    
    def log(self, URL: str = "", IP: str = "", Status: str = "true", Message: str = "") -> bool:
        pass
        try:
            with self.loggerdb:
                loggerdbCursor = self.loggerdb.cursor()
                loggerdbCursor.execute(
                    "INSERT INTO DashboardLog (LogID, URL, IP, Status, Message) VALUES (?, ?, ?, ?, ?)", (str(uuid.uuid4()), URL, IP, Status, Message,))
                if self.loggerdb.in_transaction:
                    self.loggerdb.commit()
                return True
        except Exception as e:
            print(f"[WGDashboard] Access Log Error: {str(e)}")
            return False

"""
Peer Job Logger
"""
class PeerJobLogger:
    def __init__(self):
        self.loggerdb = sqlite3.connect(os.path.join(CONFIGURATION_PATH, 'db', 'wgdashboard_log.db'),
                                     check_same_thread=False)
        self.loggerdb.row_factory = sqlite3.Row
        self.logs: List[Log] = [] 
        self.__createLogDatabase()
        
    def __createLogDatabase(self):
        with self.loggerdb:
            loggerdbCursor = self.loggerdb.cursor()
        
            existingTable = loggerdbCursor.execute("SELECT name from sqlite_master where type='table'").fetchall()
            existingTable = [t['name'] for t in existingTable]
    
            if "JobLog" not in existingTable:
                loggerdbCursor.execute("CREATE TABLE JobLog (LogID VARCHAR NOT NULL, JobID NOT NULL, LogDate DATETIME DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now', 'localtime')), Status VARCHAR NOT NULL, Message VARCHAR, PRIMARY KEY (LogID))")
                if self.loggerdb.in_transaction:
                    self.loggerdb.commit()
    def log(self, JobID: str, Status: bool = True, Message: str = "") -> bool:
        try:
            with self.loggerdb:
                loggerdbCursor = self.loggerdb.cursor()
                loggerdbCursor.execute(f"INSERT INTO JobLog (LogID, JobID, Status, Message) VALUES (?, ?, ?, ?)",
                                            (str(uuid.uuid4()), JobID, Status, Message,))
                if self.loggerdb.in_transaction:
                    self.loggerdb.commit()
        except Exception as e:
            print(f"[WGDashboard] Peer Job Log Error: {str(e)}")
            return False
        return True
    
    def getLogs(self, all: bool = False, configName = None) -> list[Log]:
        logs: list[Log] = []
        try:
            allJobs = AllPeerJobs.getAllJobs(configName)
            allJobsID = ", ".join([f"'{x.JobID}'" for x in allJobs])
            with self.loggerdb:
                loggerdbCursor = self.loggerdb.cursor()
                table = loggerdbCursor.execute(f"SELECT * FROM JobLog WHERE JobID IN ({allJobsID}) ORDER BY LogDate DESC").fetchall()
                self.logs.clear()
                for l in table:
                    logs.append(
                        Log(l["LogID"], l["JobID"], l["LogDate"], l["Status"], l["Message"]))
        except Exception as e:
            return logs
        return logs

"""
Peer Job
"""
class PeerJob:
    def __init__(self, JobID: str, Configuration: str, Peer: str,
                 Field: str, Operator: str, Value: str, CreationDate: datetime, ExpireDate: datetime, Action: str):
        self.Action = Action
        self.ExpireDate = ExpireDate
        self.CreationDate = CreationDate
        self.Value = Value
        self.Operator = Operator
        self.Field = Field
        self.Configuration = Configuration
        self.Peer = Peer
        self.JobID = JobID

    def toJson(self):
        return {
            "JobID": self.JobID,
            "Configuration": self.Configuration,
            "Peer": self.Peer,
            "Field": self.Field,
            "Operator": self.Operator,
            "Value": self.Value,
            "CreationDate": self.CreationDate,
            "ExpireDate": self.ExpireDate,
            "Action": self.Action
        }

    def __dict__(self):
        return self.toJson()

"""
Peer Jobs
"""
class PeerJobs:

    def __init__(self):
        self.Jobs: list[PeerJob] = []
        self.jobdb = sqlite3.connect(os.path.join(CONFIGURATION_PATH, 'db', 'wgdashboard_job.db'),
                                     check_same_thread=False)
        self.jobdb.row_factory = sqlite3.Row
        self.__createPeerJobsDatabase()
        self.__getJobs()

    def __getJobs(self):
        self.Jobs.clear()
        with self.jobdb:
            jobdbCursor = self.jobdb.cursor()
            jobs = jobdbCursor.execute("SELECT * FROM PeerJobs WHERE ExpireDate IS NULL").fetchall()
            for job in jobs:
                self.Jobs.append(PeerJob(
                    job['JobID'], job['Configuration'], job['Peer'], job['Field'], job['Operator'], job['Value'],
                    job['CreationDate'], job['ExpireDate'], job['Action']))
    
    def getAllJobs(self, configuration: str = None):
        if configuration is not None:
            with self.jobdb:
                jobdbCursor = self.jobdb.cursor()
                jobs = jobdbCursor.execute(
                    f"SELECT * FROM PeerJobs WHERE Configuration = ?", (configuration, )).fetchall()
                j = []
                for job in jobs:
                    j.append(PeerJob(
                        job['JobID'], job['Configuration'], job['Peer'], job['Field'], job['Operator'], job['Value'],
                        job['CreationDate'], job['ExpireDate'], job['Action']))
                return j
        return []

    def __createPeerJobsDatabase(self):
        with self.jobdb:
            jobdbCursor = self.jobdb.cursor()
        
            existingTable = jobdbCursor.execute("SELECT name from sqlite_master where type='table'").fetchall()
            existingTable = [t['name'] for t in existingTable]
    
            if "PeerJobs" not in existingTable:
                jobdbCursor.execute('''
                CREATE TABLE PeerJobs (JobID VARCHAR NOT NULL, Configuration VARCHAR NOT NULL, Peer VARCHAR NOT NULL,
                Field VARCHAR NOT NULL, Operator VARCHAR NOT NULL, Value VARCHAR NOT NULL, CreationDate DATETIME,
                ExpireDate DATETIME, Action VARCHAR NOT NULL, PRIMARY KEY (JobID))
                ''')
                self.jobdb.commit()

    def toJson(self):
        return [x.toJson() for x in self.Jobs]

    def searchJob(self, Configuration: str, Peer: str):
        return list(filter(lambda x: x.Configuration == Configuration and x.Peer == Peer, self.Jobs))

    def saveJob(self, Job: PeerJob) -> tuple[bool, list] | tuple[bool, str]:
        try:
            with self.jobdb:
                jobdbCursor = self.jobdb.cursor()
            
                if (len(str(Job.CreationDate))) == 0:
                    jobdbCursor.execute('''
                    INSERT INTO PeerJobs VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%S','now'), NULL, ?)
                    ''', (Job.JobID, Job.Configuration, Job.Peer, Job.Field, Job.Operator, Job.Value, Job.Action,))
                    JobLogger.log(Job.JobID, Message=f"Job is created if {Job.Field} {Job.Operator} {Job.Value} then {Job.Action}")
                    
                else:
                    currentJob = jobdbCursor.execute('SELECT * FROM PeerJobs WHERE JobID = ?', (Job.JobID, )).fetchone()
                    if currentJob is not None:
                        jobdbCursor.execute('''
                            UPDATE PeerJobs SET Field = ?, Operator = ?, Value = ?, Action = ? WHERE JobID = ?
                            ''', (Job.Field, Job.Operator, Job.Value, Job.Action, Job.JobID))
                        JobLogger.log(Job.JobID, 
                                      Message=f"Job is updated from if {currentJob['Field']} {currentJob['Operator']} {currentJob['value']} then {currentJob['Action']}; to if {Job.Field} {Job.Operator} {Job.Value} then {Job.Action}")
                self.jobdb.commit()
                self.__getJobs()
        
            return True, list(
                filter(lambda x: x.Configuration == Job.Configuration and x.Peer == Job.Peer and x.JobID == Job.JobID,
                       self.Jobs))
        except Exception as e:
            return False, str(e)

    def deleteJob(self, Job: PeerJob) -> tuple[bool, list] | tuple[bool, str]:
        try:
            if (len(str(Job.CreationDate))) == 0:
                return False, "Job does not exist"
            with self.jobdb:
                jobdbCursor = self.jobdb.cursor()
                jobdbCursor.execute('''
                    UPDATE PeerJobs SET ExpireDate = strftime('%Y-%m-%d %H:%M:%S','now') WHERE JobID = ?
                ''', (Job.JobID,))
                self.jobdb.commit()
            JobLogger.log(Job.JobID, Message=f"Job is removed due to being deleted or finshed.")
            self.__getJobs()
            return True, list(
                filter(lambda x: x.Configuration == Job.Configuration and x.Peer == Job.Peer and x.JobID == Job.JobID,
                       self.Jobs))
        except Exception as e:
            return False, str(e)
        
    def updateJobConfigurationName(self, ConfigurationName: str, NewConfigurationName: str) -> tuple[bool, str]:
        try:
            with self.jobdb:
                jobdbCursor = self.jobdb.cursor()
                jobdbCursor.execute('''
                        UPDATE PeerJobs SET Configuration = ? WHERE Configuration = ?
                    ''', (NewConfigurationName, ConfigurationName, ))
                self.jobdb.commit()
            self.__getJobs()
        except Exception as e:
            return False, str(e)
        
    
    def runJob(self):
        needToDelete = []
        for job in self.Jobs:
            c = WireguardConfigurations.get(job.Configuration)
            if c is not None:
                f, fp = c.searchPeer(job.Peer)
                if f:
                    if job.Field in ["total_receive", "total_sent", "total_data"]:
                        s = job.Field.split("_")[1]
                        x: float = getattr(fp, f"total_{s}") + getattr(fp, f"cumu_{s}")
                        y: float = float(job.Value)
                    else:
                        x: datetime = datetime.now()
                        y: datetime = datetime.strptime(job.Value, "%Y-%m-%d %H:%M:%S")
                    runAction: bool = self.__runJob_Compare(x, y, job.Operator)
                    if runAction:
                        s = False
                        if job.Action == "restrict":
                            s = c.restrictPeers([fp.id]).get_json()
                        elif job.Action == "delete":
                            s = c.deletePeers([fp.id]).get_json()
                
                        if s['status'] is True:
                            JobLogger.log(job.JobID, s["status"], 
                                          f"Peer {fp.id} from {c.Name} is successfully {job.Action}ed."
                            )
                            needToDelete.append(job)
                        else:
                            JobLogger.log(job.JobID, s["status"],
                                          f"Peer {fp.id} from {c.Name} failed {job.Action}ed."
                            )
                else:
                    needToDelete.append(job)
            else:
                needToDelete.append(job)
        for j in needToDelete:
            self.deleteJob(j)

    def __runJob_Compare(self, x: float | datetime, y: float | datetime, operator: str):
        if operator == "eq":
            return x == y
        if operator == "neq":
            return x != y
        if operator == "lgt":
            return x > y
        if operator == "lst":
            return x < y
        
"""
Peer Share Link
"""
class PeerShareLink:
    def __init__(self, ShareID:str, Configuration: str, Peer: str, ExpireDate: datetime, ShareDate: datetime):
        self.ShareID = ShareID
        self.Peer = Peer
        self.Configuration = Configuration
        self.ShareDate = ShareDate
        self.ExpireDate = ExpireDate
        
    
    def toJson(self):
        return {
            "ShareID": self.ShareID,
            "Peer": self.Peer,
            "Configuration": self.Configuration,
            "ExpireDate": self.ExpireDate
        }

"""
Peer Share Links
"""
class PeerShareLinks:
    def __init__(self):
        self.Links: list[PeerShareLink] = []
        existingTables = sqlSelect("SELECT name FROM sqlite_master WHERE type='table' and name = 'PeerShareLinks'").fetchall()
        if len(existingTables) == 0:
            sqlUpdate(
                """
                    CREATE TABLE PeerShareLinks (
                        ShareID VARCHAR NOT NULL PRIMARY KEY, Configuration VARCHAR NOT NULL, Peer VARCHAR NOT NULL,
                        ExpireDate DATETIME,
                        SharedDate DATETIME DEFAULT (datetime('now', 'localtime'))
                    )
                """
            )
        self.__getSharedLinks()
    
    def __getSharedLinks(self):
        self.Links.clear()
        allLinks = sqlSelect("SELECT * FROM PeerShareLinks WHERE ExpireDate IS NULL OR ExpireDate > datetime('now', 'localtime')").fetchall()
        for link in allLinks:
            self.Links.append(PeerShareLink(*link))
    
    def getLink(self, Configuration: str, Peer: str) -> list[PeerShareLink]:
        self.__getSharedLinks()
        return list(filter(lambda x : x.Configuration == Configuration and x.Peer == Peer, self.Links))
    
    def getLinkByID(self, ShareID: str) -> list[PeerShareLink]:
        self.__getSharedLinks()
        return list(filter(lambda x : x.ShareID == ShareID, self.Links))
    
    def addLink(self, Configuration: str, Peer: str, ExpireDate: datetime = None) -> tuple[bool, str]:
        try:
            newShareID = str(uuid.uuid4())
            if len(self.getLink(Configuration, Peer)) > 0:
                sqlUpdate("UPDATE PeerShareLinks SET ExpireDate = datetime('now', 'localtime') WHERE Configuration = ? AND Peer = ?", (Configuration, Peer, ))
            sqlUpdate("INSERT INTO PeerShareLinks (ShareID, Configuration, Peer, ExpireDate) VALUES (?, ?, ?, ?)", (newShareID, Configuration, Peer, ExpireDate, ))
            self.__getSharedLinks()
        except Exception as e:
            return False, str(e)
        return True, newShareID
    
    def updateLinkExpireDate(self, ShareID, ExpireDate: datetime = None) -> tuple[bool, str]:
        sqlUpdate("UPDATE PeerShareLinks SET ExpireDate = ? WHERE ShareID = ?;", (ExpireDate, ShareID, ))
        self.__getSharedLinks()
        return True, ""

"""
WireGuard Configuration
""" 


class ArchiveUtils:
    """Handles 7z archive operations with integrity checking"""
    
    @staticmethod
    def calculate_checksums(files_dict: dict) -> tuple[dict, str]:
        """
        Calculate SHA256 checksums for all files and a final combined checksum
        Returns (file_checksums, combined_checksum)
        """
        try:
            # Calculate individual file checksums
            checksums = {}
            for filename, content in sorted(files_dict.items()):  # Sort for consistent ordering
                if isinstance(content, bytes):
                    checksums[filename] = hashlib.sha256(content).hexdigest()
                elif isinstance(content, str):
                    checksums[filename] = hashlib.sha256(content.encode('utf-8')).hexdigest()
            
            # Calculate combined checksum
            combined = hashlib.sha256()
            for filename, checksum in sorted(checksums.items()):  # Sort again for consistency
                combined.update(f"{filename}:{checksum}".encode('utf-8'))
            
            return checksums, combined.hexdigest()
            
        except Exception as e:
            print(f"Error calculating checksums: {str(e)}")
            raise

    @staticmethod
    def create_archive(files_dict: dict) -> tuple[bytes, dict, str]:
        """
        Create a 7z archive with manifest and checksums
        Returns (archive_bytes, file_checksums, combined_checksum)
        """
        try:
            # Calculate checksums
            print("Calculating checksums...")
            file_checksums, combined_checksum = ArchiveUtils.calculate_checksums(files_dict)
            
            # Create manifest
            manifest = {
                'file_checksums': file_checksums,
                'combined_checksum': combined_checksum,
                'timestamp': datetime.now().isoformat(),
                'version': DashboardConfig.GetConfig("Server", "version")[1]
            }
            
            print(f"Combined checksum: {combined_checksum}")
            
            # Add manifest to files
            files_dict['wiregate_manifest.json'] = json.dumps(manifest, indent=2)
            
            print("Creating 7z archive in memory...")
            # Create archive in memory
            with tempfile.TemporaryDirectory() as temp_dir:
                # Write files
                for filename, content in files_dict.items():
                    file_path = os.path.join(temp_dir, filename)
                    # Create directories for nested paths
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    
                    if isinstance(content, str):
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                    else:
                        with open(file_path, 'wb') as f:
                            f.write(content)
                
                # Create 7z archive
                archive_buffer = io.BytesIO()
                with py7zr.SevenZipFile(archive_buffer, 'w') as archive:
                    archive.writeall(temp_dir, arcname='.')
                
                archive_data = archive_buffer.getvalue()
                print(f"Archive created successfully, size: {len(archive_data)} bytes")
                
                return archive_data, file_checksums, combined_checksum
            
        except Exception as e:
            print(f"Error creating archive: {str(e)}, {type(e)}")
            raise

    @staticmethod
    def verify_archive(archive_data: bytes) -> tuple[bool, str, dict]:
        """
        Verify 7z archive integrity using checksums
        Returns (is_valid, error_message, extracted_files)
        """
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Write archive to temp file
                archive_path = os.path.join(temp_dir, 'archive.7z')
                with open(archive_path, 'wb') as f:
                    f.write(archive_data)
                
                # Extract archive
                extracted_files = {}
                with py7zr.SevenZipFile(archive_path, 'r') as archive:
                    archive.extractall(temp_dir)
                    
                    # Read all extracted files
                    for root, _, files in os.walk(temp_dir):
                        for filename in files:
                            if filename == 'archive.7z':
                                continue
                            file_path = os.path.join(root, filename)
                            rel_path = os.path.relpath(file_path, temp_dir)
                            with open(file_path, 'rb') as f:
                                extracted_files[rel_path] = f.read()
            
            # Read manifest
            if 'wiregate_manifest.json' not in extracted_files:
                return False, "No manifest found in archive", {}
                
            try:
                manifest = json.loads(extracted_files['wiregate_manifest.json'].decode('utf-8'))
            except json.JSONDecodeError as e:
                return False, f"Invalid manifest format: {str(e)}", {}
                
            if 'file_checksums' not in manifest or 'combined_checksum' not in manifest:
                return False, "Checksums missing from manifest", {}
            
            # Verify individual file checksums
            print("Verifying individual file checksums...")
            current_checksums = {}
            for filename, content in extracted_files.items():
                if filename == 'wiregate_manifest.json':
                    continue
                    
                if filename not in manifest['file_checksums']:
                    return False, f"No checksum found for file: {filename}", {}
                    
                calculated_hash = hashlib.sha256(content).hexdigest()
                if calculated_hash != manifest['file_checksums'][filename]:
                    return False, f"Checksum mismatch for file: {filename}", {}
                current_checksums[filename] = calculated_hash
            
            # Verify combined checksum
            print("Verifying combined checksum...")
            combined = hashlib.sha256()
            for filename, checksum in sorted(current_checksums.items()):
                combined.update(f"{filename}:{checksum}".encode('utf-8'))
            
            if combined.hexdigest() != manifest['combined_checksum']:
                return False, "Combined checksum verification failed", {}
            
            print("All checksums verified successfully")
            
            # Remove manifest from extracted files
            del extracted_files['wiregate_manifest.json']
            return True, "", extracted_files
            
        except Exception as e:
            print(f"Error verifying archive: {str(e)}, {type(e)}")
            return False, f"Error verifying archive: {str(e)}", {}

class Configuration:
    class InvalidConfigurationFileException(Exception):
        def __init__(self, m):
            self.message = m

        def __str__(self):
            return self.message

    def __init__(self, name: str = None, data: dict = None, backup: dict = None, startup: bool = False):
        self.__parser: configparser.ConfigParser = configparser.ConfigParser(strict=False)
        self.__parser.optionxform = str
        self.__configFileModifiedTime = None

        self.Status: bool = False
        self.Name: str = ""
        self.PrivateKey: str = ""
        self.PublicKey: str = ""
        self.ListenPort: str = ""
        self.Address: str = ""
        self.DNS: str = ""
        self.Table: str = ""
        self.Jc: str = ""
        self.Jmin: str = ""
        self.Jmax: str = ""
        self.S1: str = ""
        self.S2: str = ""
        self.H1: str = ""
        self.H2: str = ""
        self.H3: str = ""
        self.H4: str = ""
        self.MTU: str = ""
        self.PreUp: str = ""
        self.PostUp: str = ""
        self.PreDown: str = ""
        self.PostDown: str = ""
        self.SaveConfig: bool = True
        self.Name = name
        self.Protocol = self.get_iface_proto() 

        self.configPath = os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], f'{self.Name}.conf')

        if name is not None:
            if data is not None and "Backup" in data.keys():
                db = self.__importDatabase(
                    os.path.join(
                        DashboardConfig.GetConfig("Server", "wg_conf_path")[1],
                        'WGDashboard_Backup',
                        data["Backup"].replace(".conf", ".sql")))
            else:
                self.__createDatabase()

            self.__parseConfigurationFile()
            self.__initPeersList()

        else:
            self.Name = data["ConfigurationName"]
            self.configPath = os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], f'{self.Name}.conf')

            for i in dir(self):
                if str(i) in data.keys():
                    if isinstance(getattr(self, i), bool):
                        setattr(self, i, StringToBoolean(data[i]))
                    else:
                        setattr(self, i, str(data[i]))

            self.__parser["Interface"] = {
                "PrivateKey": self.PrivateKey,
                "Address": self.Address,
                "ListenPort": self.ListenPort,
                "PreUp": self.PreUp,
                "PreDown": self.PreDown,
                "PostUp": self.PostUp,
                "PostDown": self.PostDown,
            }

            # Only add values if they are not empty or null
            if self.Jc:
                self.__parser["Interface"]["Jc"] = self.Jc
            if self.Jmin:
                self.__parser["Interface"]["Jmin"] = self.Jmin
            if self.Jmax:
                self.__parser["Interface"]["Jmax"] = self.Jmax
            if self.S1:
                self.__parser["Interface"]["S1"] = self.S1
            if self.S2:
                self.__parser["Interface"]["S2"] = self.S2
            if self.H1:
                self.__parser["Interface"]["H1"] = self.H1
            if self.H2:
                self.__parser["Interface"]["H2"] = self.H2
            if self.H3:
                self.__parser["Interface"]["H3"] = self.H3
            if self.H4:
                self.__parser["Interface"]["H4"] = self.H4

            # Add SaveConfig at the end, it seems like it's always True
            self.__parser["Interface"]["SaveConfig"] = "true"

            if "Backup" not in data.keys():
                self.__createDatabase()
                with open(self.configPath, "w+") as configFile:
                    self.__parser.write(configFile)
                self.__initPeersList()

        print(f"[WGDashboard] Initialized Configuration: {name}")    
        if self.getAutostartStatus() and not self.getStatus() and startup:
            self.toggleConfiguration()
            print(f"[WGDashboard] Autostart Configuration: {name}")

    def __initPeersList(self):
        self.Peers: list[Peer] = []
        self.getPeersList()
        self.getRestrictedPeersList()
    
    def getRawConfigurationFile(self):
        return open(self.configPath, 'r').read()
    
    def updateRawConfigurationFile(self, newRawConfiguration):
        backupStatus, backup = self.backupConfigurationFile()
        if not backupStatus:
            return False, "Cannot create backup"
    
        if self.Status:
            self.toggleConfiguration()
        
        with open(self.configPath, 'w') as f:
            f.write(newRawConfiguration)
        
        status, err = self.toggleConfiguration()
        if not status:
            restoreStatus = self.restoreBackup(backup['filename'])
            print(f"Restore status: {restoreStatus}")
            self.toggleConfiguration()
            return False, err
        return True, None
            
    def get_script_path(self, script_path):
        """
        Resolve script path relative to WireGuard config directory
        """
        if not script_path:
            return None
            
        # Get WireGuard config directory
        wg_dir = DashboardConfig.GetConfig("Server", "iptable_rules_path")[1]
        # Normalize the config directory path to remove any trailing slashes
        wg_dir = os.path.normpath(wg_dir)
        
        if script_path.startswith('/'):
            # Absolute path
            return script_path
        else:
            # Remove any leading './' from both wg_dir and script_path
            clean_wg_dir = wg_dir.strip('./')
            clean_script_path = script_path.strip('./')
            
            # Combine and normalize the path to remove any duplicates
            full_path = os.path.normpath(os.path.join(clean_wg_dir, clean_script_path))
            
            # If the original path was relative (started with ./), preserve that
            if script_path.startswith('./') or wg_dir.startswith('./'):
                full_path = './' + full_path
                
            return full_path

    def getPostUp(self):
        """Extract and resolve PostUp script path"""
        if not self.PostUp:
            return []
        
        # Split multiple commands if any
        commands = self.PostUp.split(';')
        script_paths = []
        
        for cmd in commands:
            cmd = cmd.strip()
            if cmd.endswith('.sh') or cmd.endswith('.bash'):
                # If the command is just a script path
                script_paths.append(cmd)
            else:
                # Look for script paths in command parts
                parts = cmd.split()
                for part in parts:
                    if part.endswith('.sh') or part.endswith('.bash'):
                        script_paths.append(part)
                        
        return [p for p in script_paths if p is not None]

    def getPreUp(self):
        """Extract and resolve PreUp script path"""
        if not self.PreUp:
            return []
        
        commands = self.PreUp.split(';')
        script_paths = []
        
        for cmd in commands:
            cmd = cmd.strip()
            if cmd.endswith('.sh') or cmd.endswith('.bash'):
                script_paths.append(cmd)
            else:
                parts = cmd.split()
                for part in parts:
                    if part.endswith('.sh') or part.endswith('.bash'):
                        script_paths.append(part)
                        
        return [p for p in script_paths if p is not None]

    def getPreDown(self):
        """Extract and resolve PreDown script path"""
        if not self.PreDown:
            return []
        
        commands = self.PreDown.split(';')
        script_paths = []
        
        for cmd in commands:
            cmd = cmd.strip()
            if cmd.endswith('.sh') or cmd.endswith('.bash'):
                script_paths.append(cmd)
            else:
                parts = cmd.split()
                for part in parts:
                    if part.endswith('.sh') or part.endswith('.bash'):
                        script_paths.append(part)
                        
        return [p for p in script_paths if p is not None]

    def getPostDown(self):
        """Extract and resolve PostDown script path"""
        if not self.PostDown:
            return []
        
        commands = self.PostDown.split(';')
        script_paths = []
        
        for cmd in commands:
            cmd = cmd.strip()
            if cmd.endswith('.sh') or cmd.endswith('.bash'):
                script_paths.append(cmd)
            else:
                parts = cmd.split()
                for part in parts:
                    if part.endswith('.sh') or part.endswith('.bash'):
                        script_paths.append(part)
                        
        return [p for p in script_paths if p is not None]
        
    def __parseConfigurationFile(self):
        with open(self.configPath, 'r') as f:
            original = [l.rstrip("\n") for l in f.readlines()]
            try:
                start = original.index("[Interface]")
                
                # Clean
                for i in range(start, len(original)):
                    if original[i] == "[Peer]":
                        break
                    split = re.split(r'\s*=\s*', original[i], maxsplit=1)
                    if len(split) == 2:
                        key = split[0]
                        if key in dir(self):
                            if isinstance(getattr(self, key), bool):
                                setattr(self, key, False)
                            else:
                                setattr(self, key, "")
                
                # Set
                for i in range(start, len(original)):
                    if original[i] == "[Peer]":
                        break
                    split = re.split(r'\s*=\s*', original[i], maxsplit=1)
                    if len(split) == 2:
                        key = split[0]
                        value = split[1]
                        if key in dir(self):
                            if isinstance(getattr(self, key), bool):
                                setattr(self, key, StringToBoolean(value))
                            else:
                                if len(getattr(self, key)) > 0:
                                    setattr(self, key, f"{getattr(self, key)}, {value}")
                                else:
                                    setattr(self, key, value)  
            except ValueError as e:
                raise self.InvalidConfigurationFileException(
                        "[Interface] section not found in " + self.configPath)
            if self.PrivateKey:
                self.PublicKey = self.__getPublicKey()
            self.Status = self.getStatus()
    
    def __dropDatabase(self):
        existingTables = sqlSelect(f"SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '{self.Name}%'").fetchall()
        for t in existingTables:
            sqlUpdate("DROP TABLE '%s'" % t['name'])

        existingTables = sqlSelect(f"SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '{self.Name}%'").fetchall()

    def __createDatabase(self, dbName = None):
        if dbName is None:
            dbName = self.Name
        
        existingTables = sqlSelect("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        existingTables = [t['name'] for t in existingTables]
        if dbName not in existingTables:
            sqlUpdate(
                """
                CREATE TABLE IF NOT EXISTS '%s'(
                    id VARCHAR NOT NULL, 
                    private_key VARCHAR NULL, 
                    DNS VARCHAR NULL, 
                    endpoint_allowed_ip VARCHAR NULL, 
                    name VARCHAR NULL, 
                    total_receive FLOAT NULL, 
                    total_sent FLOAT NULL, 
                    total_data FLOAT NULL, 
                    endpoint VARCHAR NULL, 
                    status VARCHAR NULL, 
                    latest_handshake VARCHAR NULL, 
                    allowed_ip VARCHAR NULL,  
                    cumu_receive FLOAT NULL, 
                    cumu_sent FLOAT NULL, 
                    cumu_data FLOAT NULL, 
                    mtu INT NULL, 
                    keepalive INT NULL, 
                    remote_endpoint VARCHAR NULL, 
                    preshared_key VARCHAR NULL,
                    address_v4 VARCHAR NULL,  
                    address_v6 VARCHAR NULL,  
                    PRIMARY KEY (id)
                )
                """ % dbName
            )

    # Create other tables with similar updates...

        if f'{dbName}_restrict_access' not in existingTables:
            sqlUpdate(
                """
                CREATE TABLE '%s_restrict_access' (
                    id VARCHAR NOT NULL, private_key VARCHAR NULL, DNS VARCHAR NULL, 
                    endpoint_allowed_ip VARCHAR NULL, name VARCHAR NULL, total_receive FLOAT NULL, 
                    total_sent FLOAT NULL, total_data FLOAT NULL, endpoint VARCHAR NULL, 
                    status VARCHAR NULL, latest_handshake VARCHAR NULL, allowed_ip VARCHAR NULL, 
                    cumu_receive FLOAT NULL, cumu_sent FLOAT NULL, cumu_data FLOAT NULL, mtu INT NULL, 
                    keepalive INT NULL, remote_endpoint VARCHAR NULL, preshared_key VARCHAR NULL,
                    address_v4 VARCHAR NULL,  
                    address_v6 VARCHAR NULL, 
                    PRIMARY KEY (id)
                )
                """ % dbName
            )
        if f'{dbName}_transfer' not in existingTables:
            sqlUpdate(
                """
                CREATE TABLE '%s_transfer' (
                    id VARCHAR NOT NULL, total_receive FLOAT NULL,
                    total_sent FLOAT NULL, total_data FLOAT NULL,
                    cumu_receive FLOAT NULL, cumu_sent FLOAT NULL, cumu_data FLOAT NULL, time DATETIME
                )
                """ % dbName
            )
        if f'{dbName}_deleted' not in existingTables:
            sqlUpdate(
                """
                CREATE TABLE '%s_deleted' (
                    id VARCHAR NOT NULL, private_key VARCHAR NULL, DNS VARCHAR NULL, 
                    endpoint_allowed_ip VARCHAR NULL, name VARCHAR NULL, total_receive FLOAT NULL, 
                    total_sent FLOAT NULL, total_data FLOAT NULL, endpoint VARCHAR NULL, 
                    status VARCHAR NULL, latest_handshake VARCHAR NULL, allowed_ip VARCHAR NULL, 
                    cumu_receive FLOAT NULL, cumu_sent FLOAT NULL, cumu_data FLOAT NULL, mtu INT NULL, 
                    keepalive INT NULL, remote_endpoint VARCHAR NULL, preshared_key VARCHAR NULL,
                    address_v4 VARCHAR NULL,  
                    address_v6 VARCHAR NULL, 
                    PRIMARY KEY (id)
                )
                """ % dbName
            )
        
    def __dumpDatabase(self):
        for line in sqldb.iterdump():
            if (line.startswith(f"INSERT INTO \"{self.Name}\"") 
                    or line.startswith(f'INSERT INTO "{self.Name}_restrict_access"')
                    or line.startswith(f'INSERT INTO "{self.Name}_transfer"')
                    or line.startswith(f'INSERT INTO "{self.Name}_deleted"')
            ):
                yield line
                
    def __importDatabase(self, sqlFilePath) -> bool:
        self.__dropDatabase()
        self.__createDatabase()
        if not os.path.exists(sqlFilePath):
            return False
            
        with open(sqlFilePath, 'r') as f:
            for l in f.readlines():
                l = l.rstrip("\n")
                if len(l) > 0:
                    # Split addresses into v4 and v6 parts before insert
                    if "INSERT INTO" in l:
                        try:
                            # Parse out address values
                            addresses = re.search(r"Address\s*=\s*'([^']*)'", l)
                            if addresses:
                                addr_parts = addresses.group(1).split(',')
                                addr_v4 = []
                                addr_v6 = []
                                for addr in addr_parts:
                                    addr = addr.strip()
                                    if ':' in addr:  # IPv6
                                        addr_v6.append(addr)
                                    else:  # IPv4
                                        addr_v4.append(addr)
                                
                                # Replace original address with split version
                                l = l.replace(
                                    f"Address = '{addresses.group(1)}'",
                                    f"address_v4 = '{','.join(addr_v4)}', address_v6 = '{','.join(addr_v6)}'"
                                )
                        except Exception as e:
                            print(f"Error parsing addresses: {e}")
                            
                    sqlUpdate(l)
        return True
        
    def __getPublicKey(self) -> str:
        return GenerateWireguardPublicKey(self.PrivateKey)[1]

    def getStatus(self) -> bool:
        self.Status = self.Name in psutil.net_if_addrs().keys()
        return self.Status
    
    def getAutostartStatus(self):
        s, d = DashboardConfig.GetConfig("WireGuardConfiguration", "autostart")
        return self.Name in d

    def __getRestrictedPeers(self):
        self.RestrictedPeers = []
        restricted = sqlSelect("SELECT * FROM '%s_restrict_access'" % self.Name).fetchall()
        for i in restricted:
            self.RestrictedPeers.append(Peer(i, self))
            
    def configurationFileChanged(self) :
        mt = os.path.getmtime(os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], f'{self.Name}.conf'))
        changed = self.__configFileModifiedTime is None or self.__configFileModifiedTime != mt
        self.__configFileModifiedTime = mt
        return changed
        
    def __getPeers(self):
        if self.configurationFileChanged():
            self.Peers = []
            with open(os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], f'{self.Name}.conf'), 'r') as configFile:
                p = []
                pCounter = -1
                content = configFile.read().split('\n')
                try:
                    peerStarts = content.index("[Peer]")
                    content = content[peerStarts:]
                    for i in content:
                        if not RegexMatch("#(.*)", i) and not RegexMatch(";(.*)", i):
                            if i == "[Peer]":
                                pCounter += 1
                                p.append({})
                                p[pCounter]["name"] = ""
                            else:
                                if len(i) > 0:
                                    split = re.split(r'\s*=\s*', i, maxsplit=1)
                                    if len(split) == 2:
                                        p[pCounter][split[0]] = split[1]
                        
                        if RegexMatch("#Name# = (.*)", i):
                            split = re.split(r'\s*=\s*', i, maxsplit=1)
                            if len(split) == 2:
                                p[pCounter]["name"] = split[1]
                    
                    for i in p:
                        if "PublicKey" in i.keys():
                            checkIfExist = sqlSelect("SELECT * FROM '%s' WHERE id = ?" % self.Name,
                                                          ((i['PublicKey']),)).fetchone()
                            if checkIfExist is None:
                                newPeer = {
                                    "id": i['PublicKey'],
                                    "private_key": "",
                                    "DNS": DashboardConfig.GetConfig("Peers", "peer_global_DNS")[1],
                                    "endpoint_allowed_ip": DashboardConfig.GetConfig("Peers", "peer_endpoint_allowed_ip")[
                                        1],
                                    "name": i.get("name"),
                                    "total_receive": 0,
                                    "total_sent": 0,
                                    "total_data": 0,
                                    "endpoint": "N/A",
                                    "status": "stopped",
                                    "latest_handshake": "N/A",
                                    "allowed_ip": i.get("AllowedIPs", "N/A"),
                                    "cumu_receive": 0,
                                    "cumu_sent": 0,
                                    "cumu_data": 0,
                                    "traffic": [],
                                    "mtu": DashboardConfig.GetConfig("Peers", "peer_mtu")[1],
                                    "keepalive": DashboardConfig.GetConfig("Peers", "peer_keep_alive")[1],
                                    "remote_endpoint": DashboardConfig.GetConfig("Peers", "remote_endpoint")[1],
                                    "preshared_key": i["PresharedKey"] if "PresharedKey" in i.keys() else ""
                                }
                                sqlUpdate(
                                    """
                                    INSERT INTO '%s'
                                        VALUES (:id, :private_key, :DNS, :endpoint_allowed_ip, :name, :total_receive, :total_sent, 
                                        :total_data, :endpoint, :status, :latest_handshake, :allowed_ip, :cumu_receive, :cumu_sent, 
                                        :cumu_data, :mtu, :keepalive, :remote_endpoint, :preshared_key);
                                    """ % self.Name
                                    , newPeer)
                                self.Peers.append(Peer(newPeer, self))
                            else:
                                sqlUpdate("UPDATE '%s' SET allowed_ip = ? WHERE id = ?" % self.Name,
                                               (i.get("AllowedIPs", "N/A"), i['PublicKey'],))
                                self.Peers.append(Peer(checkIfExist, self))
                except Exception as e:
                    if __name__ == '__main__':
                        print(f"[WGDashboard] {self.Name} Error: {str(e)}")
        else:
            self.Peers.clear()
            checkIfExist = sqlSelect("SELECT * FROM '%s'" % self.Name).fetchall()
            for i in checkIfExist:
                self.Peers.append(Peer(i, self))
            
    def addPeers(self, peers: list):
        interface_address = self.get_iface_address()
        cmd_prefix = self.get_iface_proto()
        try:
            # First, handle database updates and wg commands
            for i in peers:
                # Split addresses into v4 and v6
                addr_v4 = []
                addr_v6 = []
                if 'allowed_ip' in i:
                    for addr in i['allowed_ip'].split(','):
                        addr = addr.strip()
                        if ':' in addr:  # IPv6
                            addr_v6.append(addr)
                        else:  # IPv4
                            addr_v4.append(addr)

                newPeer = {
                    "id": i['id'],
                    "private_key": i['private_key'],
                    "DNS": i['DNS'],
                    "endpoint_allowed_ip": i['endpoint_allowed_ip'],
                    "name": i['name'],
                    "total_receive": 0,
                    "total_sent": 0,
                    "total_data": 0,
                    "endpoint": "N/A",
                    "status": "stopped",
                    "latest_handshake": "N/A",
                    "allowed_ip": i.get("allowed_ip", "N/A"),
                    "cumu_receive": 0,
                    "cumu_sent": 0,
                    "cumu_data": 0,
                    "traffic": [],
                    "mtu": i['mtu'],
                    "keepalive": i['keepalive'],
                    "remote_endpoint": DashboardConfig.GetConfig("Peers", "remote_endpoint")[1],
                    "preshared_key": i["preshared_key"],
                    "address_v4": ','.join(addr_v4) if addr_v4 else None,
                    "address_v6": ','.join(addr_v6) if addr_v6 else None
                }
                
                sqlUpdate(
                    """
                    INSERT INTO '%s'
                    VALUES (:id, :private_key, :DNS, :endpoint_allowed_ip, :name, :total_receive, :total_sent,
                    :total_data, :endpoint, :status, :latest_handshake, :allowed_ip, :cumu_receive, :cumu_sent,
                    :cumu_data, :mtu, :keepalive, :remote_endpoint, :preshared_key, :address_v4, :address_v6);
                    """ % self.Name, newPeer)

            # Handle wg commands and config file updates
            config_path = f"/etc/wireguard/{self.Name}.conf"
            for p in peers:
                presharedKeyExist = len(p['preshared_key']) > 0
                rd = random.Random()
                uid = str(uuid.UUID(int=rd.getrandbits(128), version=4))
                
                # Handle wg command
                if presharedKeyExist:
                    with open(uid, "w+") as f:
                        f.write(p['preshared_key'])
                cmd = (f"{cmd_prefix} set {self.Name} peer {p['id']} allowed-ips {p['allowed_ip'].replace(' ', '')}{f' preshared-key {uid}' if presharedKeyExist else ''}")
                subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                if presharedKeyExist:
                    os.remove(uid)
                
                # Add name comment to config file
                if 'name_comment' in p and p['name_comment']:
                    with open(config_path, 'r') as f:
                        config_lines = f.readlines()
                    
                    # Find the [Peer] section for this peer
                    peer_index = -1
                    for idx, line in enumerate(config_lines):
                        if line.strip() == '[Peer]':
                            next_lines = config_lines[idx:idx+5]  # Look at next few lines
                            for next_line in next_lines:
                                if f"PublicKey = {p['id']}" in next_line:
                                    peer_index = idx
                                    break
                    
                    # Insert name comment if we found the peer section
                    if peer_index != -1:
                        config_lines.insert(peer_index + 1, p['name_comment'] + '\n')
                        with open(config_path, 'w') as f:
                            f.writelines(config_lines)

            # Save and patch
            cmd = (f"{cmd_prefix}-quick save {self.Name}")
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            try_patch = self.patch_iface_address(interface_address)
            if try_patch:
                return try_patch
            
            self.getPeersList()
            return True
        except Exception as e:
            print(str(e))
            return False
        
    def searchPeer(self, publicKey):
        for i in self.Peers:
            if i.id == publicKey:
                return True, i
        return False, None

    def allowAccessPeers(self, listOfPublicKeys):
        if not self.getStatus():
            self.toggleConfiguration()
        interface_address = self.get_iface_address()
        cmd_prefix = self.get_iface_proto()
        for i in listOfPublicKeys:
            p = sqlSelect("SELECT * FROM '%s_restrict_access' WHERE id = ?" % self.Name, (i,)).fetchone()
            if p is not None:
                sqlUpdate("INSERT INTO '%s' SELECT * FROM %s_restrict_access WHERE id = ?"
                               % (self.Name, self.Name,), (p['id'],))
                sqlUpdate("DELETE FROM '%s_restrict_access' WHERE id = ?"
                               % self.Name, (p['id'],))
                
                presharedKeyExist = len(p['preshared_key']) > 0
                rd = random.Random()
                uid = str(uuid.UUID(int=rd.getrandbits(128), version=4))
                if presharedKeyExist:
                    with open(uid, "w+") as f:
                        f.write(p['preshared_key'])

                cmd = (f"{cmd_prefix} set {self.Name} peer {p['id']} allowed-ips {p['allowed_ip'].replace(' ', '')}{f' preshared-key {uid}' if presharedKeyExist else ''}")
                subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                
                if presharedKeyExist: os.remove(uid)
            else:
                return ResponseObject(False, "Failed to allow access of peer " + i)
        if not self.__wgSave():
            return ResponseObject(False, "Failed to save configuration through WireGuard")
        
        try_patch = self.patch_iface_address(interface_address)
        if try_patch:
            return try_patch

        self.__getPeers()
        return ResponseObject(True, "Allow access successfully")

    def restrictPeers(self, listOfPublicKeys): 
        numOfRestrictedPeers = 0
        numOfFailedToRestrictPeers = 0
        if not self.getStatus():
            self.toggleConfiguration()
        interface_address = self.get_iface_address()
        cmd_prefix = self.get_iface_proto() 
        for p in listOfPublicKeys:
            found, pf = self.searchPeer(p)
            if found:
                try:

                    cmd = (f"{cmd_prefix} set {self.Name} peer {pf.id} remove")
                    subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

                    sqlUpdate("INSERT INTO '%s_restrict_access' SELECT * FROM %s WHERE id = ?" %
                                   (self.Name, self.Name,), (pf.id,))
                    sqlUpdate("UPDATE '%s_restrict_access' SET status = 'stopped' WHERE id = ?" %
                                   (self.Name,), (pf.id,))
                    sqlUpdate("DELETE FROM '%s' WHERE id = ?" % self.Name, (pf.id,))
                    numOfRestrictedPeers += 1
                except Exception as e:
                    numOfFailedToRestrictPeers += 1

        if not self.__wgSave():
            return ResponseObject(False, "Failed to save configuration through WireGuard")
        
        try_patch = self.patch_iface_address(interface_address)
        if try_patch:
            return try_patch

        self.__getPeers()

        if numOfRestrictedPeers == len(listOfPublicKeys):
            return ResponseObject(True, f"Restricted {numOfRestrictedPeers} peer(s)")
        return ResponseObject(False,
                              f"Restricted {numOfRestrictedPeers} peer(s) successfully. Failed to restrict {numOfFailedToRestrictPeers} peer(s)")
        pass

    def deletePeers(self, listOfPublicKeys):
        numOfDeletedPeers = 0
        numOfFailedToDeletePeers = 0
        if not self.getStatus():
            self.toggleConfiguration()
        interface_address = self.get_iface_address()
        cmd_prefix = self.get_iface_proto()      
        for p in listOfPublicKeys:
            found, pf = self.searchPeer(p)
            if found:
                try:
                    #Build cmd string based off of interface protocol
                    cmd = (f"{cmd_prefix} set {self.Name} peer {pf.id} remove")
                    subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

                    sqlUpdate("DELETE FROM '%s' WHERE id = ?" % self.Name, (pf.id,))
                    numOfDeletedPeers += 1
                except Exception as e:
                    numOfFailedToDeletePeers += 1

        if not self.__wgSave():
            return ResponseObject(False, "Failed to save configuration through WireGuard")
        
        try_patch = self.patch_iface_address(interface_address)
        if try_patch:
            return try_patch

        self.__getPeers()

        if numOfDeletedPeers == len(listOfPublicKeys):
            return ResponseObject(True, f"Deleted {numOfDeletedPeers} peer(s)")
        return ResponseObject(False,
                              f"Deleted {numOfDeletedPeers} peer(s) successfully. Failed to delete {numOfFailedToDeletePeers} peer(s)")

    def get_iface_proto(self):
        try:
            # Get the path to the WireGuard configuration file
            config_path = os.path.join(
                DashboardConfig.GetConfig("Server", "wg_conf_path")[1], 
                f"{self.Name}.conf"
            )
            
            with open(config_path, "r") as conf_file:
                lines = conf_file.readlines()
            
            # Parse the [Interface] section
            interface_section = False
            awg_params = {"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"}
            found_awg_params = set()
            
            for line in lines:
                line = line.strip()
                
                if line.startswith("[Interface]"):
                    interface_section = True
                    continue
                
                # Stop parsing if another section starts
                if interface_section and line.startswith("["):
                    break
                
                if interface_section:
                    # Split the line to extract the key and value
                    if "=" in line:
                        key, _ = line.split("=", 1)
                        key = key.strip()
                        # Check if the key is in AmneziaWG parameters
                        if key in awg_params:
                            found_awg_params.add(key)
            
            # Determine if the file contains awg parameters
            if found_awg_params:
                return "awg"
            else:
                return "wg"

        except Exception as e:
            print(f"Error while parsing interface config: {e}")
            return None

    def get_iface_address(self):
        try:
            # Fetch both inet (IPv4) and inet6 (IPv6) addresses
            ipv4_address = subprocess.check_output(
                f"ip addr show {self.Name} | awk '/inet /{{print $2}}'", shell=True
            ).decode().strip()

            # Capture all IPv6 addresses (link-local and global)
            ipv6_addresses = subprocess.check_output(
                f"ip addr show {self.Name} | awk '/inet6 /{{print $2}}'", shell=True
            ).decode().splitlines()

            # Filter out potential duplicates and retain unique IPv6 addresses
            unique_ipv6_addresses = set(ipv6_addresses)
            ipv6_address = ", ".join(unique_ipv6_addresses)

            # Combine into the required format if addresses are available
            address = ipv4_address if ipv4_address else ""
            if ipv6_address:
                if address:
                    address += ", "  # Add a separator if both addresses are present
                address += ipv6_address

            return address if address else None  # Return combined address or None if no address found

        except subprocess.CalledProcessError:
            return None  # Handle errors if the command fails

    def patch_iface_address(self, interface_address):
        try:
            config_path = os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], f"{self.Name}.conf")
            with open(config_path, "r") as conf_file:
                lines = conf_file.readlines()

            # Locate the [Interface] section and the Address line
            interface_index = next((i for i, line in enumerate(lines) if line.strip() == "[Interface]"), None)
            address_line_index = next((i for i, line in enumerate(lines) if line.strip().startswith("Address")), None)

            # Create the new Address line with both IPv4 and IPv6 addresses
            address_line = f"Address = {interface_address}\n"

            # Check if the Address line exists, update it or insert after the [Interface] section
            if address_line_index is not None:
                lines[address_line_index] = address_line
            elif interface_index is not None:
                lines.insert(interface_index + 1, address_line)

            # Remove any additional Address lines (IPv4 or IPv6) to prevent duplicates
            lines = [line for i, line in enumerate(lines)
                    if not (line.strip().startswith("Address") and i != address_line_index)]

            # Write back the modified configuration to the file
            with open(config_path, "w") as conf_file:
                conf_file.writelines(lines)

        except IOError:
            return ResponseObject(False, "Failed to write the interface address to the config file")

    def __wgSave(self) -> tuple[bool, str] | tuple[bool, None]:
        cmd_prefix = self.get_iface_proto()    
        try:
            #Build cmd string based off of interface protocol
            cmd = (f"{cmd_prefix}-quick save {self.Name}")
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

            return True, None
        except subprocess.CalledProcessError as e:
            return False, str(e)

    def getPeersLatestHandshake(self):
        if not self.getStatus():
            self.toggleConfiguration()
        try:
            #Build cmd string based off of interface protocol
            cmd_prefix = self.get_iface_proto()
            cmd = (f"{cmd_prefix} show {self.Name} latest-handshakes")
            latestHandshake = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

        except subprocess.CalledProcessError:
            return "stopped"
        latestHandshake = latestHandshake.decode("UTF-8").split()
        count = 0
        now = datetime.now()
        time_delta = timedelta(minutes=2)
        for _ in range(int(len(latestHandshake) / 2)):
            minus = now - datetime.fromtimestamp(int(latestHandshake[count + 1]))
            if minus < time_delta:
                status = "running"
            else:
                status = "stopped"
            if int(latestHandshake[count + 1]) > 0:
                sqlUpdate("UPDATE '%s' SET latest_handshake = ?, status = ? WHERE id= ?" % self.Name
                              , (str(minus).split(".", maxsplit=1)[0], status, latestHandshake[count],))
            else:
                sqlUpdate("UPDATE '%s' SET latest_handshake = 'No Handshake', status = ? WHERE id= ?" % self.Name
                              , (status, latestHandshake[count],))
            count += 2
    
    def getPeersTransfer(self):
        if not self.getStatus():
            self.toggleConfiguration()
        try:
            #Build cmd string based off of interface protocol
            cmd_prefix = self.get_iface_proto()
            cmd = (f"{cmd_prefix} show {self.Name} transfer")
            data_usage = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            
            data_usage = data_usage.decode("UTF-8").split("\n")
            data_usage = [p.split("\t") for p in data_usage]
            for i in range(len(data_usage)):
                if len(data_usage[i]) == 3:
                    cur_i = sqlSelect(
                        "SELECT total_receive, total_sent, cumu_receive, cumu_sent, status FROM '%s' WHERE id= ? "
                        % self.Name, (data_usage[i][0],)).fetchone()
                    if cur_i is not None:
                        cur_i = dict(cur_i)
                        total_sent = cur_i['total_sent']
                        total_receive = cur_i['total_receive']
                        cur_total_sent = float(data_usage[i][2]) / (1024 ** 3)
                        cur_total_receive = float(data_usage[i][1]) / (1024 ** 3)
                        cumulative_receive = cur_i['cumu_receive'] + total_receive
                        cumulative_sent = cur_i['cumu_sent'] + total_sent
                        if total_sent <= cur_total_sent and total_receive <= cur_total_receive:
                            total_sent = cur_total_sent
                            total_receive = cur_total_receive
                        else:
                            sqlUpdate(
                                "UPDATE '%s' SET cumu_receive = ?, cumu_sent = ?, cumu_data = ? WHERE id = ?" %
                                self.Name, (cumulative_receive, cumulative_sent,
                                            cumulative_sent + cumulative_receive,
                                            data_usage[i][0],))
                            total_sent = 0
                            total_receive = 0
                        _, p = self.searchPeer(data_usage[i][0])
                        if p.total_receive != total_receive or p.total_sent != total_sent:
                            sqlUpdate(
                                "UPDATE '%s' SET total_receive = ?, total_sent = ?, total_data = ? WHERE id = ?"
                                % self.Name, (total_receive, total_sent,
                                              total_receive + total_sent, data_usage[i][0],))
        except Exception as e:
            print(f"[WGDashboard] {self.Name} Error: {str(e)} {str(e.__traceback__)}")

    def getPeersEndpoint(self):
        if not self.getStatus():
            self.toggleConfiguration()
        try:
            #Build cmd string based off of interface protocol
            cmd_prefix = self.get_iface_proto()
            cmd = (f"{cmd_prefix} show {self.Name} endpoints")
            data_usage = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

        except subprocess.CalledProcessError:
            return "stopped"
        data_usage = data_usage.decode("UTF-8").split()
        count = 0
        for _ in range(int(len(data_usage) / 2)):
            sqlUpdate("UPDATE '%s' SET endpoint = ? WHERE id = ?" % self.Name
                          , (data_usage[count + 1], data_usage[count],))
            count += 2

    def toggleConfiguration(self) -> tuple[bool, str]:
        self.getStatus()
        interface_address = self.get_iface_address()
        cmd_prefix = self.get_iface_proto()

        config_file_path = os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], f"{self.Name}.conf")

        if self.Status:
            try:

                cmd = (f"{cmd_prefix}-quick down {self.Name}")
                check = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)  
                #check = subprocess.check_output(f"wg-quick down {self.Name}",
                #                                shell=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as exc:
                return False, str(exc.output.strip().decode("utf-8"))
            
            # Write the interface address after bringing it down
            try_patch = self.patch_iface_address(interface_address)
            if try_patch:
                return try_patch
        else:
            try:
                # Extract IPv6 address from the WireGuard configuration file
                with open(config_file_path, 'r') as f:
                    config_data = f.read()
                
                # Extract the IPv6 address from the Address line
                ipv6_address = None
                for line in config_data.splitlines():
                    if line.strip().startswith("Address"):
                        parts = line.split("=")[1].strip().split(", ")
                        for part in parts:
                            if ":" in part:  # Check if the part looks like an IPv6 address
                                ipv6_address = part.strip()
                                break
                        if ipv6_address:
                            break
                
                # Modify the logic to continue without IPv6 if not found
                if ipv6_address:
                    # Bring the WireGuard interface up
                    cmd = (f"{cmd_prefix}-quick up {self.Name}")
                    check = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)  
                    #check = subprocess.check_output(f"wg-quick up {self.Name}",
                    #                                shell=True, stderr=subprocess.STDOUT)
                    
                    try:
                        # Remove any existing IPv6 addresses for the interface
                        remove_ipv6_cmd = f"ip -6 addr flush dev {self.Name}"
                        subprocess.check_output(remove_ipv6_cmd, shell=True, stderr=subprocess.STDOUT)
                        
                        # Add the new IPv6 address with the desired parameters
                        add_ipv6_cmd = f"ip -6 addr add {ipv6_address} dev {self.Name}"
                        subprocess.check_output(add_ipv6_cmd, shell=True, stderr=subprocess.STDOUT)
                    except subprocess.CalledProcessError as exc:
                        return False, str(exc.output.strip().decode("utf-8"))
                else:
                    # No IPv6 address found, just bring the interface up without modifying IPv6
                    cmd = (f"{cmd_prefix}-quick up {self.Name}")
                    check = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)  
                    #check = subprocess.check_output(f"wg-quick up {self.Name}",
                    #                                shell=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as exc:
                return False, str(exc.output.strip().decode("utf-8"))
        self.__parseConfigurationFile()
        self.getStatus()
        return True, None

    def getPeersList(self):
        self.__getPeers()
        return self.Peers

    def getRestrictedPeersList(self) -> list:
        self.__getRestrictedPeers()
        return self.RestrictedPeers

    def toJson(self):
        self.Status = self.getStatus()
        return {
            "Status": self.Status,
            "Name": self.Name,
            "PrivateKey": self.PrivateKey,
            "PublicKey": self.PublicKey,
            "Address": self.Address,
            "ListenPort": self.ListenPort,
            "PreUp": self.PreUp,
            "PreDown": self.PreDown,
            "PostUp": self.PostUp,
            "PostDown": self.PostDown,
            "SaveConfig": self.SaveConfig,
            "DataUsage": {
                "Total": sum(list(map(lambda x: x.cumu_data + x.total_data, self.Peers))),
                "Sent": sum(list(map(lambda x: x.cumu_sent + x.total_sent, self.Peers))),
                "Receive": sum(list(map(lambda x: x.cumu_receive + x.total_receive, self.Peers)))
            },
            "ConnectedPeers": len(list(filter(lambda x: x.status == "running", self.Peers))),
            "TotalPeers": len(self.Peers),
            "Protocol": self.Protocol,
        }
    
    def backupConfigurationFile(self):
        """Enhanced backup method that includes all iptables scripts with organized directory structure"""
        try:
            # Generate timestamp for backup files
            time_str = datetime.now().strftime("%Y%m%d%H%M%S")
            
            # Get organized backup paths
            backup_paths = get_backup_paths(self.Name, time_str)
            
            # Backup main configuration file
            shutil.copy(self.configPath, backup_paths['conf_file'])
            
            # Backup database
            with open(backup_paths['sql_file'], 'w+') as f:
                for l in self.__dumpDatabase():
                    f.write(l + "\n")
                    
            # Backup all iptables scripts if they exist
            scripts_backup = {}
            script_types = {
                'preup': ('preup', self.PreUp),
                'postup': ('postup', self.PostUp),
                'predown': ('predown', self.PreDown),
                'postdown': ('postdown', self.PostDown)
            }
            
            for script_key, (script_name, script_path) in script_types.items():
                if script_path:
                    script_file = os.path.join("./iptable-rules", f"{self.Name}-{script_name}.sh")
                    if os.path.exists(script_file):
                        with open(script_file, 'r') as f:
                            scripts_backup[f"{script_key}_script"] = f.read()
            
            # Save iptables scripts content if any exist
            if scripts_backup:
                with open(backup_paths['iptables_file'], 'w') as f:
                    json.dump(scripts_backup, f, indent=2)
            
            # Return success and backup details
            return True, {
                'filename': backup_paths['conf_file'],
                'database': backup_paths['sql_file'],
                'iptables': backup_paths['iptables_file'] if scripts_backup else None
            }
        except Exception as e:
            print(f"[WGDashboard] Backup Error: {str(e)}")
            return False, None
    
    def getBackups(self, databaseContent: bool = False) -> list[dict[str, str]]:
        """Enhanced getBackups method with organized directory structure"""
        backups = []
        
        # Get backup paths
        backup_paths = get_backup_paths(self.Name)
        
        if not os.path.exists(backup_paths['config_dir']):
            return backups
        
        # Get all files in the config backup directory
        files = [(file, os.path.getctime(os.path.join(backup_paths['config_dir'], file)))
                for file in os.listdir(backup_paths['config_dir']) 
                if os.path.isfile(os.path.join(backup_paths['config_dir'], file))]
        
        files.sort(key=lambda x: x[1], reverse=True)
        
        for f, ct in files:
            if RegexMatch(f"^({self.Name})_(.*)\\.(conf)$", f):
                s = re.search(f"^({self.Name})_(.*)\\.(conf)$", f)
                date = s.group(2)
                d = {
                    "filename": f,
                    "backupDate": date,
                    "content": open(os.path.join(backup_paths['config_dir'], f), 'r').read()
                }
                
                # Add database info if exists
                sql_file = f.replace(".conf", ".sql")
                if os.path.exists(os.path.join(backup_paths['config_dir'], sql_file)):
                    d['database'] = True
                    if databaseContent:
                        d['databaseContent'] = open(os.path.join(backup_paths['config_dir'], sql_file), 'r').read()
                        
                # Add iptables scripts info if exists
                iptables_file = f.replace(".conf", "_iptables.json")
                if os.path.exists(os.path.join(backup_paths['config_dir'], iptables_file)):
                    d['iptables_scripts'] = True
                    if databaseContent:
                        d['iptablesContent'] = open(os.path.join(backup_paths['config_dir'], iptables_file), 'r').read()
                        
                backups.append(d)
        
        return backups

    
    def restoreBackup(self, backupFileName: str) -> bool:
        """Enhanced restore method with pre/post up/down scripts"""
        backups = list(map(lambda x: x['filename'], self.getBackups()))
        if backupFileName not in backups:
            return False

        # Backup current state before restore
        self.backupConfigurationFile()
        if self.Status:
            self.toggleConfiguration()

        # Get timestamp from backup filename
        timestamp = backupFileName.split('_')[1].split('.')[0]
        backup_paths = get_backup_paths(self.Name, timestamp)
        if not os.path.exists(backup_paths['conf_file']):
            return False

        # Restore configuration file
        try:
            with open(backup_paths['conf_file'], 'r') as f:
                targetContent = f.read()
            with open(self.configPath, 'w') as f:
                f.write(targetContent)
        except Exception:
            return False

        # Parse and restore database
        self.__parseConfigurationFile()
        self.__dropDatabase()
        self.__importDatabase(backup_paths['sql_file'])
        self.__initPeersList()

        # Restore iptables scripts if they exist
        if os.path.exists(backup_paths['iptables_file']):
            try:
                with open(backup_paths['iptables_file'], 'r') as f:
                    scripts = json.load(f)
                
                # Direct mapping of script keys to filenames
                script_files = {
                    'preup_script': 'preup',
                    'postup_script': 'postup',
                    'predown_script': 'predown',
                    'postdown_script': 'postdown'
                }

                rules_dir = "./iptable-rules"
                os.makedirs(rules_dir, exist_ok=True)

                # Process each script
                for script_key, script_type in script_files.items():
                    if script_key in scripts and scripts[script_key]:  # Check if script exists and is not empty
                        script_path = os.path.join(rules_dir, f"{self.Name}-{script_type}.sh")
                        print(f"Restoring {script_key} to {script_path}")  # Debug log
                        
                        with open(script_path, 'w') as f:
                            f.write(scripts[script_key])
                        os.chmod(script_path, 0o755)

            except Exception as e:
                print(f"Warning: Failed to restore iptables scripts: {e}")
                # Continue execution even if script restoration fails
                pass

        return True


    def deleteBackup(self, backupFileName: str) -> bool:
        """Enhanced delete method with organized directory structure that handles uploaded backups"""
        backups = list(map(lambda x: x['filename'], self.getBackups()))
        if backupFileName not in backups:
            return False
            
        try:
            # Get timestamp from backup filename
            timestamp = backupFileName.split('_')[1].split('.')[0]
            backup_paths = get_backup_paths(self.Name, timestamp)
            
            files_to_delete = [
                # Regular backup files
                backup_paths['conf_file'],
                backup_paths['sql_file'],
                backup_paths['iptables_file'],
                
                # Handle potential uploaded backup files
                os.path.join(backup_paths['config_dir'], backupFileName),
                os.path.join(backup_paths['config_dir'], backupFileName.replace('.conf', '.sql')),
                os.path.join(backup_paths['config_dir'], backupFileName.replace('.conf', '_iptables.json'))
            ]
            
            # Delete all existing files
            for file_path in files_to_delete:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"[WGDashboard] Deleted backup file: {file_path}")
            
            # Clean up empty config directory
            try:
                if os.path.exists(backup_paths['config_dir']):
                    if not os.listdir(backup_paths['config_dir']):
                        os.rmdir(backup_paths['config_dir'])
                        print(f"[WGDashboard] Removed empty backup directory: {backup_paths['config_dir']}")
            except OSError as e:
                # Directory not empty or other OS error, log but continue
                print(f"[WGDashboard] Note: Could not remove backup directory: {str(e)}")
                pass
                
        except Exception as e:
            print(f"[WGDashboard] Error deleting backup files: {str(e)}")
            return False
        
        return True

    def updateConfigurationSettings(self, newData: dict) -> tuple[bool, str]:
        if self.Status:
            self.toggleConfiguration()
        original = []
        dataChanged = False
        with open(os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], f'{self.Name}.conf'), 'r') as f:
            original = f.readlines()
            original = [l.rstrip("\n") for l in original]
            allowEdit = ["Address", "PreUp", "PostUp", "PreDown", "PostDown", "ListenPost", "PrivateKey"]
            

            start = original.index("[Interface]")
            for line in range(start+1, len(original)):
                if original[line] == "[Peer]":
                    break
                split = re.split(r'\s*=\s*', original[line], 1)
                if len(split) == 2:
                    key = split[0]
                    value = split[1]
                    if key in allowEdit and key in newData.keys() and value != newData[key]:
                        split[1] = newData[key]
                        original[line] = " = ".join(split)
                        if isinstance(getattr(self, key), bool):
                            setattr(self, key, _strToBool(newData[key]))
                        else:
                            setattr(self, key, str(newData[key]))
                        dataChanged = True
                    print(original[line])
        if dataChanged:
            
            if not os.path.exists(os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], 'WGDashboard_Backup')):
                os.mkdir(os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], 'WGDashboard_Backup'))
            shutil.copy(
                os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], f'{self.Name}.conf'),
                os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], 'WGDashboard_Backup', f'{self.Name}_{datetime.now().strftime("%Y%m%d%H%M%S")}.conf')
            )
            with open(os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], f'{self.Name}.conf'), 'w') as f:
                f.write("\n".join(original))
        
        
        status, msg = self.toggleConfiguration()        
        if not status:
            return False, msg
        return True, ""

    def deleteConfiguration(self):
            if self.getStatus():
                self.toggleConfiguration()
            os.remove(self.configPath)
            self.__dropDatabase()
            return True
        
    def renameConfiguration(self, newConfigurationName) -> tuple[bool, str]:
            if newConfigurationName in WireguardConfigurations.keys():
                return False, "Configuration name already exist"
            try:
                if self.getStatus():
                    self.toggleConfiguration()
                self.__createDatabase(newConfigurationName)
                sqlUpdate(f'INSERT INTO "{newConfigurationName}" SELECT * FROM "{self.Name}"')
                sqlUpdate(f'INSERT INTO "{newConfigurationName}_restrict_access" SELECT * FROM "{self.Name}_restrict_access"')
                sqlUpdate(f'INSERT INTO "{newConfigurationName}_deleted" SELECT * FROM "{self.Name}_deleted"')
                sqlUpdate(f'INSERT INTO "{newConfigurationName}_transfer" SELECT * FROM "{self.Name}_transfer"')
                AllPeerJobs.updateJobConfigurationName(self.Name, newConfigurationName)
                shutil.copy(
                    self.configPath,
                    os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], f'{newConfigurationName}.conf')
                )
                self.deleteConfiguration()
            except Exception as e:
                return False, str(e)
            return True, None
        
    def getAvailableIP(self, all: bool = False) -> tuple[bool, list[str]] | tuple[bool, None]:
            if len(self.Address) < 0:
                return False, None
            address = self.Address.split(',')
            existedAddress = []
            availableAddress = []
            for p in self.Peers:
                if len(p.allowed_ip) > 0:
                    add = p.allowed_ip.split(',')
                    for i in add:
                        a, c = i.split('/')
                        try:
                            existedAddress.append(ipaddress.ip_address(a.replace(" ", "")))
                        except ValueError as error:
                            print(f"[WGDashboard] Error: {self.Name} peer {p.id} have invalid ip")
            for p in self.getRestrictedPeersList():
                if len(p.allowed_ip) > 0:
                    add = p.allowed_ip.split(',')
                    for i in add:
                        a, c = i.split('/')
                        existedAddress.append(ipaddress.ip_address(a.replace(" ", "")))
            for i in address:
                addressSplit, cidr = i.split('/')
                existedAddress.append(ipaddress.ip_address(addressSplit.replace(" ", "")))
            for i in address:
                network = ipaddress.ip_network(i.replace(" ", ""), False)
                count = 0
                for h in network.hosts():
                    if h not in existedAddress:
                        availableAddress.append(ipaddress.ip_network(h).compressed)
                        count += 1
                        if not all:
                            if network.version == 6 and count > 255:
                                break
            return True, availableAddress

"""
Peer
"""      
class Peer:
    def __init__(self, tableData, configuration: Configuration):
        self.configuration = configuration
        self.id = tableData["id"]
        self.private_key = tableData["private_key"]
        self.DNS = tableData["DNS"]
        self.endpoint_allowed_ip = tableData["endpoint_allowed_ip"]
        self.name = tableData["name"]
        self.total_receive = tableData["total_receive"]
        self.total_sent = tableData["total_sent"]
        self.total_data = tableData["total_data"]
        self.endpoint = tableData["endpoint"]
        self.status = tableData["status"]
        self.latest_handshake = tableData["latest_handshake"]
        self.allowed_ip = tableData["allowed_ip"]
        self.cumu_receive = tableData["cumu_receive"]
        self.cumu_sent = tableData["cumu_sent"]
        self.cumu_data = tableData["cumu_data"]
        self.mtu = tableData["mtu"]
        self.keepalive = tableData["keepalive"]
        self.remote_endpoint = tableData["remote_endpoint"]
        self.preshared_key = tableData["preshared_key"]
        self.jobs: list[PeerJob] = []
        self.ShareLink: list[PeerShareLink] = []
        self.getJobs()
        self.getShareLink()

    def toJson(self):
        self.getJobs()
        self.getShareLink()
        return self.__dict__

    def __repr__(self):
        return str(self.toJson())

    def updatePeer(self, name: str, private_key: str,
                   preshared_key: str,
                   dns_addresses: str, allowed_ip: str, endpoint_allowed_ip: str, mtu: int,
                   keepalive: int) -> ResponseObject:
        if not self.configuration.getStatus():
            self.configuration.toggleConfiguration()

        existingAllowedIps = [item for row in list(
            map(lambda x: [q.strip() for q in x.split(',')],
                map(lambda y: y.allowed_ip,
                    list(filter(lambda k: k.id != self.id, self.configuration.getPeersList()))))) for item in row]

        if allowed_ip in existingAllowedIps:
            return ResponseObject(False, "Allowed IP already taken by another peer")
        if not ValidateIPAddressesWithRange(endpoint_allowed_ip):
            return ResponseObject(False, f"Endpoint Allowed IPs format is incorrect")
        if len(dns_addresses) > 0 and not ValidateDNSAddress(dns_addresses):
            return ResponseObject(False, f"DNS format is incorrect")
        if mtu < 0 or mtu > 1460:
            return ResponseObject(False, "MTU format is not correct")
        if keepalive < 0:
            return ResponseObject(False, "Persistent Keepalive format is not correct")
        if len(private_key) > 0:
            pubKey = GenerateWireguardPublicKey(private_key)
            if not pubKey[0] or pubKey[1] != self.id:
                return ResponseObject(False, "Private key does not match with the public key")
        try:
            rd = random.Random()
            uid = str(uuid.UUID(int=rd.getrandbits(128), version=4))
            pskExist = len(preshared_key) > 0
            
            if pskExist:
                with open(uid, "w+") as f:
                    f.write(preshared_key)
            newAllowedIPs = allowed_ip.replace(" ", "")
            updateAllowedIp = subprocess.check_output(
                f"wg set {self.configuration.Name} peer {self.id} allowed-ips {newAllowedIPs} {f' preshared-key {uid}' if pskExist else 'preshared-key /dev/null'}",
                shell=True, stderr=subprocess.STDOUT)
            
            if pskExist: os.remove(uid)
            
            if len(updateAllowedIp.decode().strip("\n")) != 0:
                return ResponseObject(False,
                                      "Update peer failed when updating Allowed IPs")
            saveConfig = subprocess.check_output(f"wg-quick save {self.configuration.Name}",
                                                 shell=True, stderr=subprocess.STDOUT)
            if f"wg showconf {self.configuration.Name}" not in saveConfig.decode().strip('\n'):
                return ResponseObject(False,
                                      "Update peer failed when saving the configuration")
            sqlUpdate(
                '''UPDATE '%s' SET name = ?, private_key = ?, DNS = ?, endpoint_allowed_ip = ?, mtu = ?, 
                keepalive = ?, preshared_key = ? WHERE id = ?''' % self.configuration.Name,
                (name, private_key, dns_addresses, endpoint_allowed_ip, mtu,
                 keepalive, preshared_key, self.id,)
            )
            return ResponseObject()
        except subprocess.CalledProcessError as exc:
            return ResponseObject(False, exc.output.decode("UTF-8").strip())

    def downloadPeer(self) -> dict[str, str]:
        filename = self.name
        if len(filename) == 0:
            filename = "UntitledPeer"
        filename = "".join(filename.split(' '))
        filename = f"{filename}_{self.configuration.Name}"
        illegal_filename = [".", ",", "/", "?", "<", ">", "\\", ":", "*", '|' '\"', "com1", "com2", "com3",
                            "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4",
                            "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "con", "nul", "prn"]
        for i in illegal_filename:
            filename = filename.replace(i, "")

        peerConfiguration = f'''[Interface]
PrivateKey = {self.private_key}
Address = {self.allowed_ip}
MTU = {str(self.mtu)}
'''
        if len(self.DNS) > 0:
            peerConfiguration += f"DNS = {self.DNS}\n"

        if self.configuration.get_iface_proto() == "awg":
            peerConfiguration += f'''
Jc = {self.configuration.Jc}
Jmin = {self.configuration.Jmin}
Jmax = {self.configuration.Jmax}
S1 = {self.configuration.S1}
S2 = {self.configuration.S2}
H1 = {self.configuration.H1}
H2 = {self.configuration.H2}
H3 = {self.configuration.H3}
H4 = {self.configuration.H4}
'''


        peerConfiguration += f'''
[Peer]
PublicKey = {self.configuration.PublicKey}
AllowedIPs = {self.endpoint_allowed_ip}
Endpoint = {DashboardConfig.GetConfig("Peers", "remote_endpoint")[1]}:{self.configuration.ListenPort}
PersistentKeepalive = {str(self.keepalive)}
'''
        if len(self.preshared_key) > 0:
            peerConfiguration += f"PresharedKey = {self.preshared_key}\n"
        return {
            "fileName": filename,
            "file": peerConfiguration
        }

    def getJobs(self):
        self.jobs = AllPeerJobs.searchJob(self.configuration.Name, self.id)

    def getShareLink(self):
        self.ShareLink = AllPeerShareLinks.getLink(self.configuration.Name, self.id)
        
    def resetDataUsage(self, type):
        try:
            if type == "total":
                sqlUpdate("UPDATE '%s' SET total_data = 0, cumu_data = 0, total_receive = 0, cumu_receive = 0, total_sent = 0, cumu_sent = 0  WHERE id = ?" % self.configuration.Name, (self.id, ))
            elif type == "receive":
                sqlUpdate("UPDATE '%s' SET total_receive = 0, cumu_receive = 0 WHERE id = ?" % self.configuration.Name, (self.id, ))
            elif type == "sent":
                sqlUpdate("UPDATE '%s' SET total_sent = 0, cumu_sent = 0 WHERE id = ?" % self.configuration.Name, (self.id, ))
            else:
                return False
        except Exception as e:
            return False
        return True

"""
Dashboard API Key
"""
class DashboardAPIKey:
    def __init__(self, Key: str, CreatedAt: str, ExpiredAt: str):
        self.Key = Key
        self.CreatedAt = CreatedAt
        self.ExpiredAt = ExpiredAt
    
    def toJson(self):
        return self.__dict__

"""
Dashboard Configuration
"""
class DashboardConfig:

    def __init__(self):
        if not os.path.exists(DASHBOARD_CONF):
            open(DASHBOARD_CONF, "x")
        self.__config = configparser.ConfigParser(strict=False)
        self.__config.read_file(open(DASHBOARD_CONF, "r+"))
        self.hiddenAttribute = ["totp_key", "auth_req"]
        self.__default = {
            "Account": {
                "username": wgd_user,
                "password": wgd_pass,
                "enable_totp": "false",
                "totp_verified": "false",
                "totp_key": pyotp.random_base32()
            },
            "Server": {
                "wg_conf_path": wgd_config_path,
                "iptable_rules_path": CONFIGURATION_PATH, 
                "app_prefix": "",
                "app_ip": "0.0.0.0",
                "app_port": wgd_app_port,
                "auth_req": wgd_auth_req,
                "version": DASHBOARD_VERSION,
                "dashboard_refresh_interval": "60000",
                "dashboard_sort": "status",
                "dashboard_theme": "dark",
                "dashboard_api_key": "false",
                "dashboard_language": "en"
            },
            "Peers": {
                "peer_global_DNS": wgd_global_dns,
                "peer_endpoint_allowed_ip": wgd_peer_endpoint_allowed_ip,
                "peer_display_mode": "grid",
                "remote_endpoint": GetRemoteEndpoint(),
                "peer_MTU": wgd_mtu,
                "peer_keep_alive": wgd_keep_alive

            },
            "Other": {
                "welcome_session": wgd_welcome
            },
            "Database":{
                "type": "sqlite"
            },
            "WireGuardConfiguration": {
                "autostart": ""
            }
        }

        for section, keys in self.__default.items():
            for key, value in keys.items():
                exist, currentData = self.GetConfig(section, key)
                if not exist:
                    self.SetConfig(section, key, value, True)
        self.__createAPIKeyTable()
        self.DashboardAPIKeys = self.__getAPIKeys()
        self.APIAccessed = False
        self.SetConfig("Server", "version", DASHBOARD_VERSION)
    
    
    def __createAPIKeyTable(self):
        existingTable = sqlSelect("SELECT name FROM sqlite_master WHERE type='table' AND name = 'DashboardAPIKeys'").fetchall()
        if len(existingTable) == 0:
            sqlUpdate("CREATE TABLE DashboardAPIKeys (Key VARCHAR NOT NULL PRIMARY KEY, CreatedAt DATETIME NOT NULL DEFAULT (datetime('now', 'localtime')), ExpiredAt VARCHAR)")
    
    def __getAPIKeys(self) -> list[DashboardAPIKey]:
        keys = sqlSelect("SELECT * FROM DashboardAPIKeys WHERE ExpiredAt IS NULL OR ExpiredAt > datetime('now', 'localtime') ORDER BY CreatedAt DESC").fetchall()
        fKeys = []
        for k in keys:
            
            fKeys.append(DashboardAPIKey(*k))
        return fKeys
    
    def createAPIKeys(self, ExpiredAt = None):
        newKey = secrets.token_urlsafe(32)
        sqlUpdate('INSERT INTO DashboardAPIKeys (Key, ExpiredAt) VALUES (?, ?)', (newKey, ExpiredAt,))
        
        self.DashboardAPIKeys = self.__getAPIKeys()
        
    def deleteAPIKey(self, key):
        sqlUpdate("UPDATE DashboardAPIKeys SET ExpiredAt = datetime('now', 'localtime') WHERE Key = ?", (key, ))
        self.DashboardAPIKeys = self.__getAPIKeys()
    
    def __configValidation(self, key, value: Any) -> tuple[bool, str]:
        if type(value) is str and len(value) == 0:
            return False, "Field cannot be empty!"
        if key == "peer_global_dns":
            return ValidateDNSAddress(value)
        if key == "peer_endpoint_allowed_ip":
            value = value.split(",")
            for i in value:
                try:
                    ipaddress.ip_network(i, strict=False)
                except Exception as e:
                    return False, str(e)
        if key == "wg_conf_path":
            if not os.path.exists(value):
                return False, f"{value} is not a valid path"
        if key == "password":
            if self.GetConfig("Account", "password")[0]:
                if not self.__checkPassword(
                        value["currentPassword"], self.GetConfig("Account", "password")[1].encode("utf-8")):
                    return False, "Current password does not match."
                if value["newPassword"] != value["repeatNewPassword"]:
                    return False, "New passwords does not match"
        return True, ""

    def generatePassword(self, plainTextPassword: str):
        return bcrypt.hashpw(plainTextPassword.encode("utf-8"), bcrypt.gensalt())

    def __checkPassword(self, plainTextPassword: str, hashedPassword: bytes):
        return bcrypt.checkpw(plainTextPassword.encode("utf-8"), hashedPassword)

    def SetConfig(self, section: str, key: str, value: any, init: bool = False) -> tuple[bool, str]:
        if key in self.hiddenAttribute and not init:
            return False, None

        if not init:
            valid, msg = self.__configValidation(key, value)
            if not valid:
                return False, msg

        if section == "Account" and key == "password":
            if not init:
                value = self.generatePassword(value["newPassword"]).decode("utf-8")
            else:
                value = self.generatePassword(value).decode("utf-8")

        if section == "Server" and key == "wg_conf_path":
            if not os.path.exists(value):
                return False, "Path does not exist"

        if section not in self.__config:
            self.__config[section] = {}

        if key not in self.__config[section].keys() or value != self.__config[section][key]:
            if type(value) is bool:
                if value:
                    self.__config[section][key] = "true"
                else:
                    self.__config[section][key] = "false"
            elif type(value) in [int, float]:
                self.__config[section][key] = str(value)
            elif type(value) is list:
                self.__config[section][key] = "||".join(value).strip("||")
            else:
                self.__config[section][key] = value
            return self.SaveConfig(), ""
        return True, ""

    def SaveConfig(self) -> bool:
        try:
            with open(DASHBOARD_CONF, "w+", encoding='utf-8') as configFile:
                self.__config.write(configFile)
            return True
        except Exception as e:
            return False

    def GetConfig(self, section, key) -> tuple[bool, any]:
        if section not in self.__config:
            return False, None

        if key not in self.__config[section]:
            return False, None

        if self.__config[section][key] in ["1", "yes", "true", "on"]:
            return True, True

        if self.__config[section][key] in ["0", "no", "false", "off"]:
            return True, False
        
        if section == "WireGuardConfiguration" and key == "autostart":
            return True, list(filter(lambda x: len(x) > 0, self.__config[section][key].split("||")))

        return True, self.__config[section][key]

    def toJson(self) -> dict[str, dict[Any, Any]]:
        the_dict = {}

        for section in self.__config.sections():
            the_dict[section] = {}
            for key, val in self.__config.items(section):
                if key not in self.hiddenAttribute:
                    the_dict[section][key] = self.GetConfig(section, key)[1]
        return the_dict

"""
Database Connection Functions
"""

sqldb = sqlite3.connect(os.path.join(CONFIGURATION_PATH, 'db', 'wgdashboard.db'), check_same_thread=False)
sqldb.row_factory = sqlite3.Row
cursor = sqldb.cursor()

def sqlSelect(statement: str, paramters: tuple = ()) -> sqlite3.Cursor:
    with sqldb:
        try:
            cursor = sqldb.cursor()
            return cursor.execute(statement, paramters)

        except sqlite3.OperationalError as error:
            print("[WGDashboard] SQLite Error:" + str(error) + " | Statement: " + statement)
            return []

def sqlUpdate(statement: str, paramters: tuple = ()) -> sqlite3.Cursor:
    with sqldb:
        cursor = sqldb.cursor()
        try:
            statement = statement.rstrip(';')
            s = f'BEGIN TRANSACTION;{statement};END TRANSACTION;'
            cursor.execute(statement, paramters)
            sqldb.commit()
        except sqlite3.OperationalError as error:
            print("[WGDashboard] SQLite Error:" + str(error) + " | Statement: " + statement)


DashboardConfig = DashboardConfig()
_, APP_PREFIX = DashboardConfig.GetConfig("Server", "app_prefix")
cors = CORS(app, resources={rf"{APP_PREFIX}/api/*": {
    "origins": "*",
    "methods": "DELETE, POST, GET, OPTIONS",
    "allow_headers": ["Content-Type", "wg-dashboard-apikey"]
}})

'''
API Routes
'''

@app.before_request
def auth_req():
    if request.method.lower() == 'options':
        return ResponseObject(True)        

    DashboardConfig.APIAccessed = False
    if "api" in request.path:
        if str(request.method) == "GET":
            AllDashboardLogger.log(str(request.url), str(request.remote_addr), Message=str(request.args))
        elif str(request.method) == "POST":
            content_type = request.headers.get('Content-Type', '')
            try:
                # Attempt to parse the JSON body of the request
                body = request.get_json()
                if body is None:
                    # If get_json() returns None, the body is empty or not JSON
                    raise ValueError("Empty or invalid JSON body")
                body_repr = str(body)
            except Exception as e:
                # If parsing fails, check if Content-Type is multipart/form-data
                if 'multipart/form-data' in content_type:
                    try:
                        # Attempt to parse multipart/form-data
                        # This will not parse the body but ensures it's multipart
                        _ = request.form  # Accessing form to trigger parsing
                        body_repr = "multipart/form-data"
                    except Exception:
                        # If parsing multipart fails, respond with 415
                        response = make_response(jsonify({
                            "status": False,
                            "message": "Invalid multipart/form-data body",
                            "data": None
                        }), 415)
                        return response
                else:
                    # If Content-Type is neither JSON nor multipart/form-data, respond with 415
                    response = make_response(jsonify({
                        "status": False,
                        "message": "Unsupported Media Type. Only application/json and multipart/form-data are supported.",
                        "data": None
                    }), 415)
                    return response
            # Log the details of the POST request, including query parameters and body
            AllDashboardLogger.log(
                str(request.url),
                str(request.remote_addr),
                Message=f"Request Args: {str(request.args)} Body: {body_repr}"
            )
    
    authenticationRequired = DashboardConfig.GetConfig("Server", "auth_req")[1]
    d = request.headers
    if authenticationRequired:
        apiKey = d.get('wg-dashboard-apikey')
        apiKeyEnabled = DashboardConfig.GetConfig("Server", "dashboard_api_key")[1]
        if apiKey is not None and len(apiKey) > 0 and apiKeyEnabled:
            apiKeyExist = len(list(filter(lambda x : x.Key == apiKey, DashboardConfig.DashboardAPIKeys))) == 1
            AllDashboardLogger.log(str(request.url), str(request.remote_addr), Message=f"API Key Access: {('true' if apiKeyExist else 'false')} - Key: {apiKey}")
            if not apiKeyExist:
                DashboardConfig.APIAccessed = False
                response = Flask.make_response(app, {
                    "status": False,
                    "message": "API Key does not exist",
                    "data": None
                })
                response.content_type = "application/json"
                response.status_code = 401
                return response
            DashboardConfig.APIAccessed = True
        else:
            DashboardConfig.APIAccessed = False
            if ('/static/' not in request.path and "username" not in session 
                    and (f"{(APP_PREFIX if len(APP_PREFIX) > 0 else '')}/" != request.path 
                         and f"{(APP_PREFIX if len(APP_PREFIX) > 0 else '')}" != request.path)
                    and "validateAuthentication" not in request.path and "authenticate" not in request.path
                    and "getDashboardConfiguration" not in request.path and "getDashboardTheme" not in request.path
                    and "getDashboardVersion" not in request.path
                    and "sharePeer/get" not in request.path
                    and "isTotpEnabled" not in request.path
                    and "locale" not in request.path
            ):
                response = Flask.make_response(app, {
                    "status": False,
                    "message": "Unauthorized access.",
                    "data": None
                })
                response.content_type = "application/json"
                response.status_code = 401
                return response

@app.route(f'{APP_PREFIX}/api/handshake', methods=["GET", "OPTIONS"])
def API_Handshake():
    return ResponseObject(True)

@app.get(f'{APP_PREFIX}/api/validateAuthentication')
def API_ValidateAuthentication():
    token = request.cookies.get("authToken")
    if DashboardConfig.GetConfig("Server", "auth_req")[1]:
        if token is None or token == "" or "username" not in session or session["username"] != token:
            return ResponseObject(False, "Invalid authentication.")
    return ResponseObject(True)

@app.get(f'{APP_PREFIX}/api/requireAuthentication')
def API_RequireAuthentication():
    return ResponseObject(data=DashboardConfig.GetConfig("Server", "auth_req")[1])

@app.post(f'{APP_PREFIX}/api/authenticate')
def API_AuthenticateLogin():
    data = request.get_json()
    if not DashboardConfig.GetConfig("Server", "auth_req")[1]:
        return ResponseObject(True, DashboardConfig.GetConfig("Other", "welcome_session")[1])
    
    if DashboardConfig.APIAccessed:
        authToken = hashlib.sha256(f"{request.headers.get('wg-dashboard-apikey')}{datetime.now()}".encode()).hexdigest()
        session['username'] = authToken
        resp = ResponseObject(True, DashboardConfig.GetConfig("Other", "welcome_session")[1])
        resp.set_cookie("authToken", authToken)
        session.permanent = True
        return resp
    valid = bcrypt.checkpw(data['password'].encode("utf-8"),
                           DashboardConfig.GetConfig("Account", "password")[1].encode("utf-8"))
    totpEnabled = DashboardConfig.GetConfig("Account", "enable_totp")[1]
    totpValid = False
    if totpEnabled:
        totpValid = pyotp.TOTP(DashboardConfig.GetConfig("Account", "totp_key")[1]).now() == data['totp']

    if (valid
            and data['username'] == DashboardConfig.GetConfig("Account", "username")[1]
            and ((totpEnabled and totpValid) or not totpEnabled)
    ):
        authToken = hashlib.sha256(f"{data['username']}{datetime.now()}".encode()).hexdigest()
        session['username'] = authToken
        resp = ResponseObject(True, DashboardConfig.GetConfig("Other", "welcome_session")[1])
        resp.set_cookie("authToken", authToken)
        session.permanent = True
        AllDashboardLogger.log(str(request.url), str(request.remote_addr), Message=f"Login success: {data['username']}")
        return resp
    AllDashboardLogger.log(str(request.url), str(request.remote_addr), Message=f"Login failed: {data['username']}")
    if totpEnabled:
        return ResponseObject(False, "Sorry, your username, password or OTP is incorrect.")
    else:
        return ResponseObject(False, "Sorry, your username or password is incorrect.")

@app.get(f'{APP_PREFIX}/api/signout')
def API_SignOut():
    resp = ResponseObject(True, "")
    resp.delete_cookie("authToken")
    return resp

@app.route(f'{APP_PREFIX}/api/getConfigurations', methods=["GET"])
def API_getConfigurations():
    InitWireguardConfigurationsList()
    return ResponseObject(data=[wc for wc in WireguardConfigurations.values()])

@app.route(f'{APP_PREFIX}/api/addConfiguration', methods=["POST"])
def API_addConfiguration():
    data = request.get_json()
    requiredKeys = [
        "ConfigurationName", "Address", "ListenPort", "PrivateKey"
    ]
    for i in requiredKeys:
        if i not in data.keys():
            return ResponseObject(False, "Please provide all required parameters.")

    # Check duplicate names, ports, address
    for i in WireguardConfigurations.values():
        if i.Name == data['ConfigurationName']:
            return ResponseObject(False,
                                f"Already have a configuration with the name \"{data['ConfigurationName']}\"",
                                "ConfigurationName")
        if str(i.ListenPort) == str(data["ListenPort"]):
            return ResponseObject(False,
                                f"Already have a configuration with the port \"{data['ListenPort']}\"",
                                "ListenPort")
        if i.Address == data["Address"]:
            return ResponseObject(False,
                                f"Already have a configuration with the address \"{data['Address']}\"",
                                "Address")

    # Create iptables-rules directory if it doesn't exist
    iptables_dir = "./iptable-rules"
    if not os.path.exists(iptables_dir):
        try:
            os.makedirs(iptables_dir)
        except Exception as e:
            return ResponseObject(False, f"Failed to create iptables directory: {str(e)}")

    backup_mode = "Backup" in data.keys()
    
    if backup_mode:
        # Existing backup mode handling
        config_name = data["Backup"].split("_")[0]
        backup_paths = get_backup_paths(config_name)
        backup_file = os.path.join(backup_paths['config_dir'], data["Backup"])
        backup_sql = os.path.join(backup_paths['config_dir'], data["Backup"].replace('.conf', '.sql'))
        backup_iptables = os.path.join(backup_paths['config_dir'], data["Backup"].replace('.conf', '_iptables.json'))
        
        if not os.path.exists(backup_file):
            return ResponseObject(False, "Backup configuration file does not exist")
            
        # Copy configuration file
        try:
            wg_conf_path = os.path.join(
                DashboardConfig.GetConfig("Server", "wg_conf_path")[1],
                f'{data["ConfigurationName"]}.conf'
            )
            shutil.copy(backup_file, wg_conf_path)
        except Exception as e:
            return ResponseObject(False, f"Failed to copy configuration file: {str(e)}")
            
        # Create and initialize the configuration
        try:
            WireguardConfigurations[data['ConfigurationName']] = Configuration(
                name=data['ConfigurationName']
            )
        except Exception as e:
            if os.path.exists(wg_conf_path):
                os.remove(wg_conf_path)
            return ResponseObject(False, f"Failed to initialize configuration: {str(e)}")

        # Restore database if it exists
        if os.path.exists(backup_sql):
            try:
                with open(backup_sql, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            # Update table names to match new configuration name
                            line = line.replace(
                                f'"{data["Backup"].split("_")[0]}"', 
                                f'"{data["ConfigurationName"]}"'
                            )
                            sqlUpdate(line)
            except Exception as e:
                # Cleanup on failure
                WireguardConfigurations[data['ConfigurationName']].deleteConfiguration()
                WireguardConfigurations.pop(data['ConfigurationName'])
                return ResponseObject(False, f"Failed to restore database: {str(e)}")

        # Restore iptables scripts if they exist
        if os.path.exists(backup_iptables):
            try:
                with open(backup_iptables, 'r') as f:
                    scripts = json.load(f)
                
                # Map of script types to configuration attributes and file suffixes
                script_mapping = {
                    'preup_script': ('PreUp', '-preup.sh'),
                    'postup_script': ('PostUp', '-postup.sh'),
                    'predown_script': ('PreDown', '-predown.sh'),
                    'postdown_script': ('PostDown', '-postdown.sh')
                }
                
                # Create and restore all script types
                for script_key, (config_attr, suffix) in script_mapping.items():
                    if script_key in scripts:
                        script_path = os.path.join(iptables_dir, f"{data['ConfigurationName']}{suffix}")
                        with open(script_path, 'w') as f:
                            f.write(scripts[script_key])
                        os.chmod(script_path, 0o755)
                        
                        # Update configuration's corresponding attribute to point to new script
                        setattr(WireguardConfigurations[data['ConfigurationName']], 
                                config_attr, 
                                script_path)

            except Exception as e:
                # Cleanup on failure
                WireguardConfigurations[data['ConfigurationName']].deleteConfiguration()
                WireguardConfigurations.pop(data['ConfigurationName'])
                return ResponseObject(False, f"Failed to restore iptables scripts: {str(e)}")


    else:
        # Handle new configuration creation with all IPTables scripts
        try:
            config_name = data['ConfigurationName']
            
            # Create all IPTables scripts (PreUp, PostUp, PreDown, PostDown)
            script_types = {
                'PreUp': '-preup.sh',
                'PostUp': '-postup.sh',
                'PreDown': '-predown.sh',
                'PostDown': '-postdown.sh'
            }
            
            script_paths = {}
            for script_type, suffix in script_types.items():
                if script_type in data and data.get(script_type):
                    script_path = os.path.join(iptables_dir, f"{config_name}{suffix}")
                    with open(script_path, 'w') as f:
                        f.write("#!/bin/bash\n\n")
                        f.write(f"# IPTables {script_type} Rules for {config_name}\n")
                        f.write(data.get(script_type, ''))
                    os.chmod(script_path, 0o755)
                    script_paths[script_type] = script_path

            # Update data with script paths for Configuration creation
            for script_type, path in script_paths.items():
                data[script_type] = path

            # Create the configuration
            WireguardConfigurations[config_name] = Configuration(data=data)

        except Exception as e:
            # Cleanup on failure - remove any created script files
            for script_path in script_paths.values():
                if os.path.exists(script_path):
                    try:
                        os.remove(script_path)
                    except:
                        pass
            return ResponseObject(False, f"Failed to create configuration: {str(e)}")

    # Handle AmneziaWG specific setup
    if data.get("Protocol") == "awg":
        try:
            conf_file_path = os.path.join(wgd_config_path, f'{data["ConfigurationName"]}.conf')
            symlink_path = os.path.join("/etc/amnezia/amneziawg", f'{data["ConfigurationName"]}.conf')

            if not os.path.islink(symlink_path):
                os.symlink(conf_file_path, symlink_path)
                print(f"Created symbolic link: {symlink_path} -> {conf_file_path}")
            else:
                print(f"Symbolic link for {data['ConfigurationName']} already exists, skipping...")

        except Exception as e:
            print(f"Warning: Failed to create AmneziaWG symlink: {str(e)}")

    return ResponseObject()

@app.get(f'{APP_PREFIX}/api/toggleConfiguration/')
def API_toggleConfiguration():
    configurationName = request.args.get('configurationName')
    if configurationName is None or len(
            configurationName) == 0 or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide a valid configuration name")
    toggleStatus, msg = WireguardConfigurations[configurationName].toggleConfiguration()
    return ResponseObject(toggleStatus, msg, WireguardConfigurations[configurationName].Status)

@app.post(f'{APP_PREFIX}/api/updateConfiguration')
def API_updateConfiguration():
    data = request.get_json()
    requiredKeys = ["Name"]
    for i in requiredKeys:
        if i not in data.keys():
            return ResponseObject(False, "Please provide these following field: " + ", ".join(requiredKeys))
    name = data.get("Name")
    if name not in WireguardConfigurations.keys():
        return ResponseObject(False, "Configuration does not exist")
    
    status, msg = WireguardConfigurations[name].updateConfigurationSettings(data)
    
    return ResponseObject(status, message=msg, data=WireguardConfigurations[name])


'''
Edit Raw Config API
'''

@app.get(f'{APP_PREFIX}/api/getConfigurationRawFile')
def API_GetConfigurationRawFile():
    configurationName = request.args.get('configurationName')
    if configurationName is None or len(
            configurationName) == 0 or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide a valid configuration name")
    
    return ResponseObject(data={
        "path": WireguardConfigurations[configurationName].configPath,
        "content": WireguardConfigurations[configurationName].getRawConfigurationFile()
    })

@app.post(f'{APP_PREFIX}/api/updateConfigurationRawFile')
def API_UpdateConfigurationRawFile():
    data = request.get_json()
    configurationName = data.get('configurationName')
    rawConfiguration = data.get('rawConfiguration')
    if configurationName is None or len(
            configurationName) == 0 or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide a valid configuration name")
    if rawConfiguration is None or len(rawConfiguration) == 0:
        return ResponseObject(False, "Please provide content")
    
    status, err = WireguardConfigurations[configurationName].updateRawConfigurationFile(rawConfiguration)

    return ResponseObject(status=status, message=err)



'''
Iptable Script Get API
'''

@app.post(f'{APP_PREFIX}/api/getConfigTablesPreUp')
def API_GetConfigTablesPreUp():
    data = request.get_json()
    configurationName = data.get('configurationName')
    if configurationName is None or len(
            configurationName) == 0 or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide a valid configuration name")
    
    script_paths = WireguardConfigurations[configurationName].getPreUp()
    
    if not script_paths:
        return ResponseObject(False, "No PreUp scripts found")
    
    script_contents = {}
    for path in script_paths:
        try:
            with open(path, 'r') as f:
                script_contents[path] = f.read()
        except (IOError, OSError) as e:
            script_contents[path] = f"Error reading file: {str(e)}"
    
    return ResponseObject(data={
        "paths": script_paths,
        "contents": script_contents,
        "raw_preup": WireguardConfigurations[configurationName].PreUp
    })

@app.post(f'{APP_PREFIX}/api/getConfigTablesPostUp')
def API_GetConfigTablesPostUp():
    data = request.get_json()
    configurationName = data.get('configurationName')
    if configurationName is None or len(
            configurationName) == 0 or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide a valid configuration name")
    
    script_paths = WireguardConfigurations[configurationName].getPostUp()
    
    if not script_paths:
        return ResponseObject(False, "No PostUp scripts found")
    
    script_contents = {}
    for path in script_paths:
        try:
            with open(path, 'r') as f:
                script_contents[path] = f.read()
        except (IOError, OSError) as e:
            script_contents[path] = f"Error reading file: {str(e)}"
    
    return ResponseObject(data={
        "paths": script_paths,
        "contents": script_contents,
        "raw_postup": WireguardConfigurations[configurationName].PostUp
    })

@app.post(f'{APP_PREFIX}/api/getConfigTablesPostDown')
def API_GetConfigTablesPostDown():
    data = request.get_json()
    configurationName = data.get('configurationName')
    if configurationName is None or len(
            configurationName) == 0 or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide a valid configuration name")
    
    script_paths = WireguardConfigurations[configurationName].getPostDown()
    
    if not script_paths:
        return ResponseObject(False, "No PostDown scripts found")
    
    script_contents = {}
    for path in script_paths:
        try:
            with open(path, 'r') as f:
                script_contents[path] = f.read()
        except (IOError, OSError) as e:
            script_contents[path] = f"Error reading file: {str(e)}"
    
    return ResponseObject(data={
        "paths": script_paths,
        "contents": script_contents,
        "raw_postdown": WireguardConfigurations[configurationName].PostDown
    })

@app.post(f'{APP_PREFIX}/api/getConfigTablesPreDown')
def API_GetConfigTablesPreDown():
    data = request.get_json()
    configurationName = data.get('configurationName')
    if configurationName is None or len(
            configurationName) == 0 or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide a valid configuration name")
    
    script_paths = WireguardConfigurations[configurationName].getPreDown()
    
    if not script_paths:
        return ResponseObject(False, "No PreDown scripts found")
    
    script_contents = {}
    for path in script_paths:
        try:
            with open(path, 'r') as f:
                script_contents[path] = f.read()
        except (IOError, OSError) as e:
            script_contents[path] = f"Error reading file: {str(e)}"
    
    return ResponseObject(data={
        "paths": script_paths,
        "contents": script_contents,
        "raw_predown": WireguardConfigurations[configurationName].PreDown
    })



'''
Iptable Script Update API
'''

@app.post(f'{APP_PREFIX}/api/updateConfigTablesPreUp')
def API_UpdateConfigTablesPreUp():
    data = request.get_json()
    configurationName = data.get('configurationName')
    script_content = data.get('content')
    
    if configurationName is None or len(
            configurationName) == 0 or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide a valid configuration name")
    
    if script_content is None:
        return ResponseObject(False, "Please provide script content")
        
    config = WireguardConfigurations[configurationName]
    script_paths = config.getPreUp()
    
    if not script_paths:
        return ResponseObject(False, "No PreUp script path found")
        
    try:
        # Update each script file
        for path in script_paths:
            with open(path, 'w') as f:
                f.write(script_content)
            # Make executable
            os.chmod(path, 0o755)
            
        return ResponseObject(True, "PreUp script updated successfully")
    except Exception as e:
        return ResponseObject(False, f"Failed to update script: {str(e)}")

@app.post(f'{APP_PREFIX}/api/updateConfigTablesPostUp')
def API_UpdateConfigTablesPostUp():
    data = request.get_json()
    configurationName = data.get('configurationName')
    script_content = data.get('content')
    
    if configurationName is None or len(
            configurationName) == 0 or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide a valid configuration name")
    
    if script_content is None:
        return ResponseObject(False, "Please provide script content")
        
    config = WireguardConfigurations[configurationName]
    script_paths = config.getPostUp()
    
    if not script_paths:
        return ResponseObject(False, "No PostUp script path found")
        
    try:
        # Update each script file
        for path in script_paths:
            with open(path, 'w') as f:
                f.write(script_content)
            # Make executable
            os.chmod(path, 0o755)
            
        return ResponseObject(True, "PostUp script updated successfully")
    except Exception as e:
        return ResponseObject(False, f"Failed to update script: {str(e)}")

@app.post(f'{APP_PREFIX}/api/updateConfigTablesPreDown')
def API_UpdateConfigTablesPreDown():
    data = request.get_json()
    configurationName = data.get('configurationName')
    script_content = data.get('content')
    
    if configurationName is None or len(
            configurationName) == 0 or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide a valid configuration name")
    
    if script_content is None:
        return ResponseObject(False, "Please provide script content")
        
    config = WireguardConfigurations[configurationName]
    script_paths = config.getPreDown()
    
    if not script_paths:
        return ResponseObject(False, "No PreDown script path found")
        
    try:
        # Update each script file
        for path in script_paths:
            with open(path, 'w') as f:
                f.write(script_content)
            # Make executable
            os.chmod(path, 0o755)
            
        return ResponseObject(True, "PreDown script updated successfully")
    except Exception as e:
        return ResponseObject(False, f"Failed to update script: {str(e)}")

@app.post(f'{APP_PREFIX}/api/updateConfigTablesPostDown')
def API_UpdateConfigTablesPostDown():
    data = request.get_json()
    configurationName = data.get('configurationName')
    script_content = data.get('content')
    
    if configurationName is None or len(
            configurationName) == 0 or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide a valid configuration name")
    
    if script_content is None:
        return ResponseObject(False, "Please provide script content")
        
    config = WireguardConfigurations[configurationName]
    script_paths = config.getPostDown()
    
    if not script_paths:
        return ResponseObject(False, "No PostDown script path found")
        
    try:
        # Update each script file
        for path in script_paths:
            with open(path, 'w') as f:
                f.write(script_content)
            # Make executable
            os.chmod(path, 0o755)
            
        return ResponseObject(True, "PostDown script updated successfully")
    except Exception as e:
        return ResponseObject(False, f"Failed to update script: {str(e)}")

@app.post(f'{APP_PREFIX}/api/deleteConfiguration')
def API_deleteWireguardConfiguration():
    data = request.get_json()
    if "Name" not in data.keys() or data.get("Name") is None or data.get("Name") not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide the configuration name you want to delete")
    
    config_name = data.get("Name")
    
    # Delete iptables script files before deleting configuration
    script_types = ['-preup.sh', '-postup.sh', '-predown.sh', '-postdown.sh']
    iptables_dir = "./iptable-rules"
    
    for script_suffix in script_types:
        script_path = os.path.join(iptables_dir, f"{config_name}{script_suffix}")
        try:
            if os.path.exists(script_path):
                os.remove(script_path)
                print(f"Deleted iptables script: {script_path}")
        except Exception as e:
            print(f"Warning: Failed to delete iptables script {script_path}: {str(e)}")
    
    # Delete the configuration
    status = WireguardConfigurations[config_name].deleteConfiguration()
    
    if status:
        WireguardConfigurations.pop(config_name)
    return ResponseObject(status)

@app.post(f'{APP_PREFIX}/api/renameConfiguration')
def API_renameConfiguration():
    data = request.get_json()
    keys = ["Name", "NewConfigurationName"]
    for k in keys:
        if (k not in data.keys() or data.get(k) is None or len(data.get(k)) == 0 or 
                (k == "Name" and data.get(k) not in WireguardConfigurations.keys())): 
            return ResponseObject(False, "Please provide the configuration name you want to rename")
        
    status, message = WireguardConfigurations[data.get("Name")].renameConfiguration(data.get("NewConfigurationName"))
    if status:
        WireguardConfigurations.pop(data.get("Name"))
        WireguardConfigurations[data.get("NewConfigurationName")] = Configuration(data.get("NewConfigurationName"))
    return ResponseObject(status, message)

@app.get(f'{APP_PREFIX}/api/getConfigurationBackup')
def API_getConfigurationBackup():
    """Get backups for a specific configuration with organized structure"""
    configurationName = request.args.get('configurationName')
    if configurationName is None or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Configuration does not exist")
    return ResponseObject(data=WireguardConfigurations[configurationName].getBackups())

@app.get(f'{APP_PREFIX}/api/getAllConfigurationBackup')
def API_getAllConfigurationBackup():
    """Get all configuration backups with organized structure"""
    data = {
        "ExistingConfigurations": {},
        "NonExistingConfigurations": {}
    }
    
    # Get base backup directory
    backup_dir = os.path.join(DashboardConfig.GetConfig("Server", "wg_conf_path")[1], 'WGDashboard_Backup')
    
    # Handle existing configurations
    existingConfiguration = WireguardConfigurations.keys()
    for config_name in existingConfiguration:
        backups = WireguardConfigurations[config_name].getBackups(True)
        if backups:
            data['ExistingConfigurations'][config_name] = backups

    # Handle non-existing configurations
    if os.path.exists(backup_dir):
        # Look for backup directories that don't match existing configurations
        for dir_name in os.listdir(backup_dir):
            dir_path = os.path.join(backup_dir, dir_name)
            if os.path.isdir(dir_path) and dir_name not in existingConfiguration:
                backups = []
                files = [(f, os.path.getctime(os.path.join(dir_path, f)))
                        for f in os.listdir(dir_path)
                        if os.path.isfile(os.path.join(dir_path, f))]
                files.sort(key=lambda x: x[1], reverse=True)

                for f, _ in files:
                    if RegexMatch(r"^(.*)_(.*)\.(conf)$", f):
                        s = re.search(r"^(.*)_(.*)\.(conf)$", f)
                        date = s.group(2)
                        backup_info = {
                            "filename": f,
                            "backupDate": date,
                            "content": open(os.path.join(dir_path, f), 'r').read()
                        }

                        # Check for associated backup files
                        sql_file = f.replace(".conf", ".sql")
                        if os.path.exists(os.path.join(dir_path, sql_file)):
                            backup_info['database'] = True
                            backup_info['databaseContent'] = open(os.path.join(dir_path, sql_file), 'r').read()

                        iptables_file = f.replace(".conf", "_iptables.json")
                        if os.path.exists(os.path.join(dir_path, iptables_file)):
                            backup_info['iptables_scripts'] = True
                            with open(os.path.join(dir_path, iptables_file), 'r') as iptables_f:
                                backup_info['iptablesContent'] = iptables_f.read()

                        backups.append(backup_info)

                if backups:
                    data['NonExistingConfigurations'][dir_name] = backups

    return ResponseObject(data=data)

@app.get(f'{APP_PREFIX}/api/createConfigurationBackup')
def API_createConfigurationBackup():
    """Create a backup for a specific configuration using organized structure"""
    configurationName = request.args.get('configurationName')
    if configurationName is None or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Configuration does not exist")
    
    success = WireguardConfigurations[configurationName].backupConfigurationFile()
    return ResponseObject(
        status=success,
        data=WireguardConfigurations[configurationName].getBackups() if success else None
    )

@app.post(f'{APP_PREFIX}/api/deleteConfigurationBackup')
def API_DeleteConfigurationBackup():
    try:
        data = request.get_json()
        if 'configurationName' not in data or 'backupFileName' not in data:
            return ResponseObject(False, "Missing required parameters")

        config_name = data['configurationName']
        backup_file = data['backupFileName']
        
        # Get backup paths
        backup_timestamp = backup_file.replace(f'{config_name}_', '').replace('.conf', '')
        backup_paths = get_backup_paths(config_name, backup_timestamp)
        
        # Delete backup files if they exist
        files_to_delete = [
            backup_paths['conf_file'],
            backup_paths['sql_file'],
            backup_paths['iptables_file']
        ]
        
        for file_path in files_to_delete:
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Check if config backup directory is empty and remove it if so
        if len(os.listdir(backup_paths['config_dir'])) == 0:
            os.rmdir(backup_paths['config_dir'])
            
        return ResponseObject(True, "Backup deleted successfully")
        
    except Exception as e:
        logging.error(f"Error deleting backup: {str(e)}")
        return ResponseObject(False, f"Failed to delete backup: {str(e)}")


@app.post(f'{APP_PREFIX}/api/restoreConfigurationBackup')
def API_restoreConfigurationBackup():
    """Restore a backup using organized structure"""
    try:
        if request.is_json:
            data = request.get_json()
            configuration_name = data.get("configurationName")
            backup_file_name = data.get("backupFileName")
            backup_file = None
            
            if not configuration_name or not backup_file_name:
                return ResponseObject(False, "Configuration name and backup file name are required")
                
        else:
            backup_file = request.files.get("backupFile")
            if not backup_file:
                return ResponseObject(False, "No backup file uploaded")
            
            # Extract configuration name from backup filename
            backup_filename = backup_file.filename
            match = re.search(r"^(.+?)_\d{14}_complete\.7z$", backup_filename)
            if not match:
                return ResponseObject(False, f"Invalid backup filename format: {backup_filename}")
            
            configuration_name = match.group(1)
            backup_file_name = None

        # Create temp directory for processing
        temp_dir = os.path.join(
            DashboardConfig.GetConfig("Server", "wg_conf_path")[1],
            'WGDashboard_Backup',
            'temp'
        )
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)

        try:
            if backup_file:
                # Handle uploaded 7z file
                if not backup_file.filename.endswith('.7z'):
                    return ResponseObject(False, "Uploaded file must be a .7z archive")

                # Save uploaded file
                file_path = os.path.join(temp_dir, backup_file.filename)
                backup_file.save(file_path)

                # Verify and extract the archive
                is_valid, error_msg, extracted_files = ArchiveUtils.verify_archive(
                    open(file_path, 'rb').read()
                )
                
                if not is_valid:
                    return ResponseObject(False, f"Invalid backup archive: {error_msg}")

                # Create configuration if it doesn't exist
                if configuration_name not in WireguardConfigurations.keys():
                    WireguardConfigurations[configuration_name] = Configuration(configuration_name)

                # Get backup paths for the configuration
                backup_paths = get_backup_paths(configuration_name)
                
                # Save extracted files to appropriate locations
                for filename, content in extracted_files.items():
                    if filename.startswith('iptable-rules/'):
                        # Handle iptables rules
                        rules_dir = os.path.join(
                            DashboardConfig.GetConfig("Server", "iptable_rules_path")[1]
                        )
                        os.makedirs(rules_dir, exist_ok=True)
                        file_path = os.path.join(rules_dir, os.path.basename(filename))
                    else:
                        # Handle regular backup files
                        file_path = os.path.join(backup_paths['config_dir'], filename)
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    
                    with open(file_path, 'wb') as f:
                        f.write(content)
                    
                    if filename.endswith('.sh'):
                        os.chmod(file_path, 0o755)

            else:
                # Handle native backup restore
                if configuration_name not in WireguardConfigurations.keys():
                    return ResponseObject(False, "Configuration does not exist")
                
                success = WireguardConfigurations[configuration_name].restoreBackup(backup_file_name)
                if not success:
                    return ResponseObject(False, "Failed to restore backup")

            return ResponseObject(True, "Backup restored successfully")

        finally:
            # Clean up temp directory
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    except Exception as e:
        return ResponseObject(False, f"Error restoring backup: {str(e)}")

@app.get(f'{APP_PREFIX}/api/downloadConfigurationBackup')
def API_downloadConfigurationBackup():
    """Download a backup with enhanced script handling"""
    try:
        config_name = request.args.get('configurationName')
        backup_name = request.args.get('backupFileName')
        print(f"Download requested for config: {config_name}, backup: {backup_name}")
        
        if not config_name or not backup_name:
            return ResponseObject(False, "Configuration name and backup filename are required")
        
        # Get timestamp from backup filename
        timestamp = backup_name.split('_')[1].split('.')[0]
        backup_paths = get_backup_paths(config_name, timestamp)
        
        if not os.path.exists(backup_paths['conf_file']):
            return ResponseObject(False, "Backup file not found")
        
        try:
            # Collect all backup files
            files_dict = {}
            
            # Add main configuration file
            with open(backup_paths['conf_file'], 'rb') as f:
                files_dict[os.path.basename(backup_paths['conf_file'])] = f.read()
            
            # Add SQL backup if it exists
            if os.path.exists(backup_paths['sql_file']):
                with open(backup_paths['sql_file'], 'rb') as f:
                    files_dict[os.path.basename(backup_paths['sql_file'])] = f.read()
            
            # Add iptables backup if it exists
            if os.path.exists(backup_paths['iptables_file']):
                # First add the iptables.json file itself
                with open(backup_paths['iptables_file'], 'rb') as f:
                    files_dict[os.path.basename(backup_paths['iptables_file'])] = f.read()
                
                # Then process the scripts referenced in iptables.json
                with open(backup_paths['iptables_file'], 'r') as f:
                    scripts = json.load(f)
                # Include all script files if they exist
                script_types = ['preup', 'postup', 'predown', 'postdown']
                for script_type in script_types:
                    script_key = f"{script_type}_script"
                    if script_key in scripts:
                        script_name = f"{config_name}-{script_type}.sh"
                        script_path = os.path.join("./iptable-rules", script_name)
                        if os.path.exists(script_path):
                            with open(script_path, 'rb') as sf:
                                files_dict[f"iptable-rules/{script_name}"] = sf.read()
                        
            # Create archive with integrity checks
            archive_data, _, combined_checksum = ArchiveUtils.create_archive(files_dict)
            
            # Create response
            response = make_response(archive_data)
            response.headers['Content-Type'] = 'application/x-7z-compressed'
            response.headers['Content-Disposition'] = \
                f'attachment; filename="{config_name}_{timestamp}_complete.7z"'
            response.headers['Content-Length'] = len(archive_data)
            response.headers['X-Archive-Checksum'] = combined_checksum
            
            return response
            
        except Exception as e:
            return ResponseObject(False, f"Error creating backup archive: {str(e)}")
            
    except Exception as e:
        return ResponseObject(False, f"Error processing download request: {str(e)}")

@app.post(f'{APP_PREFIX}/api/uploadConfigurationBackup')
def API_uploadConfigurationBackup():
    """Upload and process a backup using organized structure"""
    try:
        if 'files' not in request.files:
            return ResponseObject(False, "No file part in request")
            
        files = request.files.getlist('files')
        if not files or len(files) != 1:
            return ResponseObject(False, "Please upload exactly one backup archive")

        file = files[0]
        if file.filename == '':
            return ResponseObject(False, "File name is empty")
            
        if not file.filename.endswith('.7z'):
            return ResponseObject(False, "Only .7z backup archives are allowed")

        # Extract configuration name from filename
        match = re.search(r"^(.+?)_\d{14}_complete\.7z$", file.filename)
        if not match:
            return ResponseObject(False, f"Invalid backup filename format: {file.filename}")
            
        config_name = match.group(1)
        backup_paths = get_backup_paths(config_name)

        # Read and verify the archive
        archive_data = file.read()
        is_valid, error_msg, extracted_files = ArchiveUtils.verify_archive(archive_data)
        
        if not is_valid:
            return ResponseObject(False, f"Invalid backup archive: {error_msg}")

        # Save verified files to appropriate locations
        saved_files = []
        for filename, content in extracted_files.items():
            # Skip iptables rules files as they're handled by restoreConfig
            if filename.startswith('iptable-rules/'):
                continue
                
            # Handle regular backup files
            file_path = os.path.join(backup_paths['config_dir'], filename)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'wb') as f:
                f.write(content)
            saved_files.append(filename)
            
            if filename.endswith('.sh'):
                os.chmod(file_path, 0o755)

        return ResponseObject(
            True,
            "Backup archive verified and extracted successfully",
            {"saved_files": saved_files}
        )

    except Exception as e:
        return ResponseObject(False, f"Error processing backup: {str(e)}")




@app.get(f'{APP_PREFIX}/api/getDashboardConfiguration')
def API_getDashboardConfiguration():
    return ResponseObject(data=DashboardConfig.toJson())

@app.post(f'{APP_PREFIX}/api/updateDashboardConfigurationItem')
def API_updateDashboardConfigurationItem():
    data = request.get_json()
    if "section" not in data.keys() or "key" not in data.keys() or "value" not in data.keys():
        return ResponseObject(False, "Invalid request.")
    valid, msg = DashboardConfig.SetConfig(
        data["section"], data["key"], data['value'])
    if not valid:
        return ResponseObject(False, msg)
    
    if data['section'] == "Server":
        if data['key'] == 'wg_conf_path':
            WireguardConfigurations.clear()
            InitWireguardConfigurationsList()
            
    return ResponseObject(True, data=DashboardConfig.GetConfig(data["section"], data["key"])[1])

@app.get(f'{APP_PREFIX}/api/getDashboardAPIKeys')
def API_getDashboardAPIKeys():
    if DashboardConfig.GetConfig('Server', 'dashboard_api_key'):
        return ResponseObject(data=DashboardConfig.DashboardAPIKeys)
    return ResponseObject(False, "WGDashboard API Keys function is disabled")

@app.post(f'{APP_PREFIX}/api/newDashboardAPIKey')
def API_newDashboardAPIKey():
    data = request.get_json()
    if DashboardConfig.GetConfig('Server', 'dashboard_api_key'):
        try:
            if data['neverExpire']:
                expiredAt = None
            else:
                expiredAt = datetime.strptime(data['ExpiredAt'], '%Y-%m-%d %H:%M:%S')
            DashboardConfig.createAPIKeys(expiredAt)
            return ResponseObject(True, data=DashboardConfig.DashboardAPIKeys)
        except Exception as e:
            return ResponseObject(False, str(e))
    return ResponseObject(False, "Dashboard API Keys function is disbaled")

@app.post(f'{APP_PREFIX}/api/deleteDashboardAPIKey')
def API_deleteDashboardAPIKey():
    data = request.get_json()
    if DashboardConfig.GetConfig('Server', 'dashboard_api_key'):
        if len(data['Key']) > 0 and len(list(filter(lambda x : x.Key == data['Key'], DashboardConfig.DashboardAPIKeys))) > 0:
            DashboardConfig.deleteAPIKey(data['Key'])
            return ResponseObject(True, data=DashboardConfig.DashboardAPIKeys)
    return ResponseObject(False, "Dashboard API Keys function is disbaled")
    
@app.post(f'{APP_PREFIX}/api/updatePeerSettings/<configName>')
def API_updatePeerSettings(configName):
    data = request.get_json()
    id = data['id']
    if len(id) > 0 and configName in WireguardConfigurations.keys():
        name = data['name']
        private_key = data['private_key']
        dns_addresses = data['DNS']
        allowed_ip = data['allowed_ip']
        endpoint_allowed_ip = data['endpoint_allowed_ip']
        preshared_key = data['preshared_key']
        mtu = data['mtu']
        keepalive = data['keepalive']
        wireguardConfig = WireguardConfigurations[configName]
        foundPeer, peer = wireguardConfig.searchPeer(id)
        if foundPeer:
            return peer.updatePeer(name, private_key, preshared_key, dns_addresses,
                                   allowed_ip, endpoint_allowed_ip, mtu, keepalive)
    return ResponseObject(False, "Peer does not exist")

@app.post(f'{APP_PREFIX}/api/resetPeerData/<configName>')
def API_resetPeerData(configName):
    data = request.get_json()
    id = data['id']
    type = data['type']
    if len(id) == 0 or configName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Configuration/Peer does not exist")
    wgc = WireguardConfigurations.get(configName)
    foundPeer, peer = wgc.searchPeer(id)
    if not foundPeer:
        return ResponseObject(False, "Configuration/Peer does not exist")
    return ResponseObject(status=peer.resetDataUsage(type))

@app.post(f'{APP_PREFIX}/api/deletePeers/<configName>')
def API_deletePeers(configName: str) -> ResponseObject:
    data = request.get_json()
    peers = data['peers']
    if configName in WireguardConfigurations.keys():
        if len(peers) == 0:
            return ResponseObject(False, "Please specify one or more peers")
        configuration = WireguardConfigurations.get(configName)
        return configuration.deletePeers(peers)

    return ResponseObject(False, "Configuration does not exist")

@app.post(f'{APP_PREFIX}/api/restrictPeers/<configName>')
def API_restrictPeers(configName: str) -> ResponseObject:
    data = request.get_json()
    peers = data['peers']
    if configName in WireguardConfigurations.keys():
        if len(peers) == 0:
            return ResponseObject(False, "Please specify one or more peers")
        configuration = WireguardConfigurations.get(configName)
        return configuration.restrictPeers(peers)
    return ResponseObject(False, "Configuration does not exist")

@app.post(f'{APP_PREFIX}/api/sharePeer/create')
def API_sharePeer_create():
    data: dict[str, str] = request.get_json()
    Configuration = data.get('Configuration')
    Peer = data.get('Peer')
    ExpireDate = data.get('ExpireDate')
    if Configuration is None or Peer is None:
        return ResponseObject(False, "Please specify configuration and peers")
    activeLink = AllPeerShareLinks.getLink(Configuration, Peer)
    if len(activeLink) > 0:
        return ResponseObject(True, 
                              "This peer is already sharing. Please view data for shared link.",
                                data=activeLink[0]
        )
    status, message = AllPeerShareLinks.addLink(Configuration, Peer, ExpireDate)
    if not status:
        return ResponseObject(status, message)
    return ResponseObject(data=AllPeerShareLinks.getLinkByID(message))

@app.post(f'{APP_PREFIX}/api/sharePeer/update')
def API_sharePeer_update():
    data: dict[str, str] = request.get_json()
    ShareID: str = data.get("ShareID")
    ExpireDate: str = data.get("ExpireDate")
    
    if ShareID is None:
        return ResponseObject(False, "Please specify ShareID")
    
    if len(AllPeerShareLinks.getLinkByID(ShareID)) == 0:
        return ResponseObject(False, "ShareID does not exist")
    
    status, message = AllPeerShareLinks.updateLinkExpireDate(ShareID, ExpireDate)
    if not status:
        return ResponseObject(status, message)
    return ResponseObject(data=AllPeerShareLinks.getLinkByID(ShareID))

@app.get(f'{APP_PREFIX}/api/sharePeer/get')
def API_sharePeer_get():
    data = request.args
    ShareID = data.get("ShareID")
    if ShareID is None or len(ShareID) == 0:
        return ResponseObject(False, "Please provide ShareID")
    link = AllPeerShareLinks.getLinkByID(ShareID)
    if len(link) == 0:
        return ResponseObject(False, "This link is either expired to invalid")
    l = link[0]
    if l.Configuration not in WireguardConfigurations.keys():
        return ResponseObject(False, "The peer you're looking for does not exist")
    c = WireguardConfigurations.get(l.Configuration)
    fp, p = c.searchPeer(l.Peer)
    if not fp:
        return ResponseObject(False, "The peer you're looking for does not exist")
    
    return ResponseObject(data=p.downloadPeer())
    
@app.post(f'{APP_PREFIX}/api/allowAccessPeers/<configName>')
def API_allowAccessPeers(configName: str) -> ResponseObject:
    data = request.get_json()
    peers = data['peers']
    if configName in WireguardConfigurations.keys():
        if len(peers) == 0:
            return ResponseObject(False, "Please specify one or more peers")
        configuration = WireguardConfigurations.get(configName)
        return configuration.allowAccessPeers(peers)
    return ResponseObject(False, "Configuration does not exist")

@app.post(f'{APP_PREFIX}/api/addPeers/<configName>')
def API_addPeers(configName):
    if configName in WireguardConfigurations.keys():
        try:
            data: dict = request.get_json()

            bulkAdd: bool = data.get("bulkAdd", False)
            bulkAddAmount: int = data.get('bulkAddAmount', 0)
            preshared_key_bulkAdd: bool = data.get('preshared_key_bulkAdd', False)
    
    
            public_key: str = data.get('public_key', "")
            allowed_ips: list[str] = data.get('allowed_ips', "")
            
            endpoint_allowed_ip: str = data.get('endpoint_allowed_ip', DashboardConfig.GetConfig("Peers", "peer_endpoint_allowed_ip")[1])
            dns_addresses: str = data.get('DNS', DashboardConfig.GetConfig("Peers", "peer_global_DNS")[1])
            mtu: int = data.get('mtu', int(DashboardConfig.GetConfig("Peers", "peer_MTU")[1]))
            keep_alive: int = data.get('keepalive', int(DashboardConfig.GetConfig("Peers", "peer_keep_alive")[1]))
            preshared_key: str = data.get('preshared_key', "")
            
    
            if type(mtu) is not int or mtu < 0 or mtu > 1460:
                mtu = int(DashboardConfig.GetConfig("Peers", "peer_MTU")[1])
            if type(keep_alive) is not int or keep_alive < 0:
                keep_alive = int(DashboardConfig.GetConfig("Peers", "peer_keep_alive")[1])
            if len(dns_addresses) == 0:
                dns_addresses = DashboardConfig.GetConfig("Peers", "peer_global_DNS")[1]
            if len(endpoint_allowed_ip) == 0:
                endpoint_allowed_ip = DashboardConfig.GetConfig("Peers", "peer_endpoint_allowed_ip")[1]
            config = WireguardConfigurations.get(configName)
            if not bulkAdd and (len(public_key) == 0 or len(allowed_ips) == 0):
                return ResponseObject(False, "Please provide at least public_key and allowed_ips")
            if not config.getStatus():
                config.toggleConfiguration()
            availableIps = config.getAvailableIP()
            if bulkAdd:
                if type(preshared_key_bulkAdd) is not bool:
                    preshared_key_bulkAdd = False
                
                if type(bulkAddAmount) is not int or bulkAddAmount < 1:
                    return ResponseObject(False, "Please specify amount of peers you want to add")
                if not availableIps[0]:
                    return ResponseObject(False, "No more available IP can assign")
                if bulkAddAmount > len(availableIps[1]):
                    return ResponseObject(False,
                                          f"The maximum number of peers can add is {len(availableIps[1])}")
                keyPairs = []
                for i in range(bulkAddAmount):
                    newPrivateKey = GenerateWireguardPrivateKey()[1]
                    keyPairs.append({
                        "private_key": newPrivateKey,
                        "id": GenerateWireguardPublicKey(newPrivateKey)[1],
                        "preshared_key": (GenerateWireguardPrivateKey()[1] if preshared_key_bulkAdd else ""),
                        "allowed_ip": availableIps[1][i],
                        "name": f"BulkPeer #{(i + 1)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        "DNS": dns_addresses,
                        "endpoint_allowed_ip": endpoint_allowed_ip,
                        "mtu": mtu,
                        "keepalive": keep_alive
                    })
                if len(keyPairs) == 0:
                    return ResponseObject(False, "Generating key pairs by bulk failed")
                config.addPeers(keyPairs)
                return ResponseObject()
    
            else:
                if config.searchPeer(public_key)[0] is True:
                    return ResponseObject(False, f"This peer already exist")
                name = data.get("name", "")
                private_key = data.get("private_key", "")
    
                for i in allowed_ips:
                    if i not in availableIps[1]:
                        return ResponseObject(False, f"This IP is not available: {i}")
    
                status = config.addPeers([
                    {
                        "name": name,
                        "id": public_key,
                        "private_key": private_key,
                        "allowed_ip": ','.join(allowed_ips),
                        "preshared_key": preshared_key,
                        "endpoint_allowed_ip": endpoint_allowed_ip,
                        "DNS": dns_addresses,
                        "mtu": mtu,
                        "keepalive": keep_alive
                    }]
                )
                return ResponseObject(status)
        except Exception as e:
            print(e)
            return ResponseObject(False, "Add peers failed. Please see data for specific issue")

    return ResponseObject(False, "Configuration does not exist")

@app.get(f"{APP_PREFIX}/api/downloadPeer/<configName>")
def API_downloadPeer(configName):
    data = request.args
    if configName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Configuration does not exist")
    configuration = WireguardConfigurations[configName]
    peerFound, peer = configuration.searchPeer(data['id'])
    if len(data['id']) == 0 or not peerFound:
        return ResponseObject(False, "Peer does not exist")
    return ResponseObject(data=peer.downloadPeer())

@app.get(f"{APP_PREFIX}/api/downloadAllPeers/<configName>")
def API_downloadAllPeers(configName):
    if configName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Configuration does not exist")
    configuration = WireguardConfigurations[configName]
    peerData = []
    untitledPeer = 0
    for i in configuration.Peers:
        file = i.downloadPeer()
        if file["fileName"] == "UntitledPeer_" + configName:
            file["fileName"] = str(untitledPeer) + "_" + file["fileName"]
            untitledPeer += 1
        peerData.append(file)
    return ResponseObject(data=peerData)

@app.get(f"{APP_PREFIX}/api/getAvailableIPs/<configName>")
def API_getAvailableIPs(configName):
    if configName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Configuration does not exist")
    status, ips = WireguardConfigurations.get(configName).getAvailableIP()
    return ResponseObject(status=status, data=ips)

@app.get(f'{APP_PREFIX}/api/getWireguardConfigurationInfo')
def API_getConfigurationInfo():
    configurationName = request.args.get("configurationName")
    if not configurationName or configurationName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please provide configuration name")
    return ResponseObject(data={
        "configurationInfo": WireguardConfigurations[configurationName],
        "configurationPeers": WireguardConfigurations[configurationName].getPeersList(),
        "configurationRestrictedPeers": WireguardConfigurations[configurationName].getRestrictedPeersList()
    })

@app.get(f'{APP_PREFIX}/api/getDashboardTheme')
def API_getDashboardTheme():
    return ResponseObject(data=DashboardConfig.GetConfig("Server", "dashboard_theme")[1])

@app.get(f'{APP_PREFIX}/api/getDashboardVersion')
def API_getDashboardVersion():
    return ResponseObject(data=DashboardConfig.GetConfig("Server", "version")[1])

@app.get(f'{APP_PREFIX}/api/getDashboardProto')
def API_getDashboardProto():
    return ResponseObject(data=DashboardConfig.GetConfig("Server", "protocol")[1])

@app.post(f'{APP_PREFIX}/api/savePeerScheduleJob/')
def API_savePeerScheduleJob():
    data = request.json
    if "Job" not in data.keys() not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please specify job")
    job: dict = data['Job']
    if "Peer" not in job.keys() or "Configuration" not in job.keys():
        return ResponseObject(False, "Please specify peer and configuration")
    configuration = WireguardConfigurations.get(job['Configuration'])
    f, fp = configuration.searchPeer(job['Peer'])
    if not f:
        return ResponseObject(False, "Peer does not exist")

    s, p = AllPeerJobs.saveJob(PeerJob(
        job['JobID'], job['Configuration'], job['Peer'], job['Field'], job['Operator'], job['Value'],
        job['CreationDate'], job['ExpireDate'], job['Action']))
    if s:
        return ResponseObject(s, data=p)
    return ResponseObject(s, message=p)

@app.post(f'{APP_PREFIX}/api/deletePeerScheduleJob/')
def API_deletePeerScheduleJob():
    data = request.json
    if "Job" not in data.keys() not in WireguardConfigurations.keys():
        return ResponseObject(False, "Please specify job")
    job: dict = data['Job']
    if "Peer" not in job.keys() or "Configuration" not in job.keys():
        return ResponseObject(False, "Please specify peer and configuration")
    configuration = WireguardConfigurations.get(job['Configuration'])
    f, fp = configuration.searchPeer(job['Peer'])
    if not f:
        return ResponseObject(False, "Peer does not exist")

    s, p = AllPeerJobs.deleteJob(PeerJob(
        job['JobID'], job['Configuration'], job['Peer'], job['Field'], job['Operator'], job['Value'],
        job['CreationDate'], job['ExpireDate'], job['Action']))
    if s:
        return ResponseObject(s, data=p)
    return ResponseObject(s, message=p)

@app.get(f'{APP_PREFIX}/api/getPeerScheduleJobLogs/<configName>')
def API_getPeerScheduleJobLogs(configName):
    if configName not in WireguardConfigurations.keys():
        return ResponseObject(False, "Configuration does not exist")
    data = request.args.get("requestAll")
    requestAll = False
    if data is not None and data == "true":
        requestAll = True
    return ResponseObject(data=JobLogger.getLogs(requestAll, configName))

'''
Tools
'''

@app.get(f'{APP_PREFIX}/api/ping/getAllPeersIpAddress')
def API_ping_getAllPeersIpAddress():
    ips = {}
    for c in WireguardConfigurations.values():
        cips = {}
        for p in c.Peers:
            allowed_ip = p.allowed_ip.replace(" ", "").split(",")
            parsed = []
            for x in allowed_ip:
                try:
                    ip = ipaddress.ip_network(x, strict=False)
                except ValueError as e:
                    print(f"{p.id} - {c.Name}")
                if len(list(ip.hosts())) == 1:
                    parsed.append(str(ip.hosts()[0]))
            endpoint = p.endpoint.replace(" ", "").replace("(none)", "")
            if len(p.name) > 0:
                cips[f"{p.name} - {p.id}"] = {
                    "allowed_ips": parsed,
                    "endpoint": endpoint
                }
            else:
                cips[f"{p.id}"] = {
                    "allowed_ips": parsed,
                    "endpoint": endpoint
                }
        ips[c.Name] = cips
    return ResponseObject(data=ips)

import requests

@app.get(f'{APP_PREFIX}/api/ping/execute')
def API_ping_execute():
    if "ipAddress" in request.args.keys() and "count" in request.args.keys():
        ip = request.args['ipAddress']
        count = request.args['count']
        try:
            if ip is not None and len(ip) > 0 and count is not None and count.isnumeric():
                result = ping(ip, count=int(count), source=None)
                
                data = {
                    "address": result.address,
                    "is_alive": result.is_alive,
                    "min_rtt": result.min_rtt,
                    "avg_rtt": result.avg_rtt,
                    "max_rtt": result.max_rtt,
                    "package_sent": result.packets_sent,
                    "package_received": result.packets_received,
                    "package_loss": result.packet_loss,
                    "geo": None
                }
                
                
                try:
                    r = requests.get(f"http://ip-api.com/json/{result.address}?field=city")
                    data['geo'] = r.json()
                except Exception as e:
                    pass
                return ResponseObject(data=data)
            return ResponseObject(False, "Please specify an IP Address (v4/v6)")
        except Exception as exp:
            return ResponseObject(False, exp)
    return ResponseObject(False, "Please provide ipAddress and count")

@app.get(f'{APP_PREFIX}/api/traceroute/execute')
def API_traceroute_execute():
    if "ipAddress" in request.args.keys() and len(request.args.get("ipAddress")) > 0:
        ipAddress = request.args.get('ipAddress')
        try:
            tracerouteResult = traceroute(ipAddress, timeout=1, max_hops=64)
            result = []
            for hop in tracerouteResult:
                if len(result) > 1:
                    skipped = False
                    for i in range(result[-1]["hop"] + 1, hop.distance):
                        result.append(
                            {
                                "hop": i,
                                "ip": "*",
                                "avg_rtt": "*",
                                "min_rtt": "*",
                                "max_rtt": "*"
                            }
                        )
                        skip = True
                    if skipped: continue
                result.append(
                    {
                        "hop": hop.distance,
                        "ip": hop.address,
                        "avg_rtt": hop.avg_rtt,
                        "min_rtt": hop.min_rtt,
                        "max_rtt": hop.max_rtt
                    })
            try:
                r = requests.post(f"http://ip-api.com/batch?fields=city,country,lat,lon,query",
                                  data=json.dumps([x['ip'] for x in result]))
                d = r.json()
                for i in range(len(result)):
                    result[i]['geo'] = d[i]
                
            except Exception as e:
                print(e)
            return ResponseObject(data=result)
        except Exception as exp:
            return ResponseObject(False, exp)
    else:
        return ResponseObject(False, "Please provide ipAddress")

@app.get(f'{APP_PREFIX}/api/getDashboardUpdate')
def API_getDashboardUpdate():
    try:
        # Replace with your actual Docker Hub repository
        docker_hub_repo = "noxcis/wiregate"
        
        # Docker Hub API URL to list tags
        list_tags_url = f"https://hub.docker.com/v2/repositories/{docker_hub_repo}/tags"
        
        # Send a request to Docker Hub to list all tags
        response = requests.get(list_tags_url, timeout=5)
        
        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            tags_data = response.json()
            
            # Get the results (list of tags)
            tags = tags_data.get('results', [])
            
            if not tags:
                return ResponseObject(False, "No tags found in the repository")
            
            # Create a list to store parsed tags with their details
            parsed_tags = []
            
            # Iterate through tags and parse details
            for tag in tags:
                try:
                    # Extract tag name and last pushed timestamp
                    tag_name = tag.get('name', '')
                    
                    # Use tag_last_pushed for most accurate timestamp
                    last_pushed_str = tag.get('tag_last_pushed', tag.get('last_updated', ''))
                    
                    # Convert timestamp to datetime
                    if last_pushed_str:
                        last_pushed = datetime.fromisoformat(last_pushed_str.replace('Z', '+00:00'))
                        
                        parsed_tags.append({
                            'name': tag_name,
                            'last_pushed': last_pushed
                        })
                except Exception as tag_parse_error:
                    logging.error(f"Error parsing tag {tag}: {tag_parse_error}")
            
            # Sort tags by last pushed date
            if parsed_tags:
                sorted_tags = sorted(parsed_tags, key=lambda x: x['last_pushed'], reverse=True)
                latest_tag = sorted_tags[0]['name']
                latest_pushed = sorted_tags[0]['last_pushed']
                
                # Create Docker Hub URL
                docker_hub_url = f"https://hub.docker.com/r/{docker_hub_repo}/tags?page=1&name={latest_tag}"
                
                # Compare with current version
                if latest_tag and latest_tag != DASHBOARD_VERSION:
                    return ResponseObject(
                        message=f"IMAGE:[{latest_tag}] is now available for update!", 
                        data=docker_hub_url
                    )
                else:
                    return ResponseObject(
                        message="You're on the latest version", 
                        data=docker_hub_url
                    )
            
            return ResponseObject(False, "Unable to parse tags")
        
        # If request was not successful
        return ResponseObject(False, f"API request failed with status {response.status_code}")
    
    except requests.RequestException as e:
        logging.error(f"Request to Docker Hub API failed: {str(e)}")
        return ResponseObject(False, f"Request failed: {str(e)}")
    except Exception as e:
        logging.error(f"Unexpected error in Docker Hub update check: {str(e)}")
        return ResponseObject(False, f"Unexpected error: {str(e)}")

'''
Sign Up
'''

@app.get(f'{APP_PREFIX}/api/isTotpEnabled')
def API_isTotpEnabled():
    return (
        ResponseObject(data=DashboardConfig.GetConfig("Account", "enable_totp")[1] and DashboardConfig.GetConfig("Account", "totp_verified")[1]))

@app.get(f'{APP_PREFIX}/api/Welcome_GetTotpLink')
def API_Welcome_GetTotpLink():
    if not DashboardConfig.GetConfig("Account", "totp_verified")[1]:
        DashboardConfig.SetConfig("Account", "totp_key", pyotp.random_base32())
        return ResponseObject(
            data=pyotp.totp.TOTP(DashboardConfig.GetConfig("Account", "totp_key")[1]).provisioning_uri(
                issuer_name="WireGate"))
    return ResponseObject(False)

@app.post(f'{APP_PREFIX}/api/Welcome_VerifyTotpLink')
def API_Welcome_VerifyTotpLink():
    data = request.get_json()
    totp = pyotp.TOTP(DashboardConfig.GetConfig("Account", "totp_key")[1]).now()
    if totp == data['totp']:
        DashboardConfig.SetConfig("Account", "totp_verified", "true")
        DashboardConfig.SetConfig("Account", "enable_totp", "true")
    return ResponseObject(totp == data['totp'])

@app.post(f'{APP_PREFIX}/api/Welcome_Finish')
def API_Welcome_Finish():
    data = request.get_json()
    if DashboardConfig.GetConfig("Other", "welcome_session")[1]:
        if data["username"] == "":
            return ResponseObject(False, "Username cannot be blank.")

        if data["newPassword"] == "" or len(data["newPassword"]) < 8:
            return ResponseObject(False, "Password must be at least 8 characters")

        updateUsername, updateUsernameErr = DashboardConfig.SetConfig("Account", "username", data["username"])
        updatePassword, updatePasswordErr = DashboardConfig.SetConfig("Account", "password",
                                                                      {
                                                                          "newPassword": data["newPassword"],
                                                                          "repeatNewPassword": data["repeatNewPassword"],
                                                                          "currentPassword": "admin"
                                                                      })
        if not updateUsername or not updatePassword:
            return ResponseObject(False, f"{updateUsernameErr},{updatePasswordErr}".strip(","))

        DashboardConfig.SetConfig("Other", "welcome_session", False)
    return ResponseObject()

class Locale:
    def __init__(self):
        self.localePath = './static/locale/'
        self.activeLanguages = {}
        with open(os.path.join(f"{self.localePath}active_languages.json"), "r") as f:
            self.activeLanguages = json.loads(''.join(f.readlines()))
        
    
    def getLanguage(self) -> dict | None:
        currentLanguage = DashboardConfig.GetConfig("Server", "dashboard_language")[1]
        if currentLanguage == "en":
            return None
        if os.path.exists(os.path.join(f"{self.localePath}{currentLanguage}.json")):
            with open(os.path.join(f"{self.localePath}{currentLanguage}.json"), "r") as f:
                return dict(json.loads(''.join(f.readlines())))
        else:
            return None
    
    def updateLanguage(self, lang_id):
        if not os.path.exists(os.path.join(f"{self.localePath}{lang_id}.json")):
            DashboardConfig.SetConfig("Server", "dashboard_language", "en")
        else:
            DashboardConfig.SetConfig("Server", "dashboard_language", lang_id)
         
Locale = Locale()

@app.get(f'{APP_PREFIX}/api/locale')
def API_Locale_CurrentLang():    
    return ResponseObject(data=Locale.getLanguage())

@app.get(f'{APP_PREFIX}/api/locale/available')
def API_Locale_Available():
    return ResponseObject(data=Locale.activeLanguages)
        
@app.post(f'{APP_PREFIX}/api/locale/update')
def API_Locale_Update():
    data = request.get_json()
    if 'lang_id' not in data.keys():
        return ResponseObject(False, "Please specify a lang_id")
    Locale.updateLanguage(data['lang_id'])
    return ResponseObject(data=Locale.getLanguage())

@app.get(f'{APP_PREFIX}/api/systemStatus')
def API_SystemStatus():
    try:
        # CPU Information
        try:
            cpu_percpu = psutil.cpu_percent(interval=0.5, percpu=True)
            cpu = psutil.cpu_percent(interval=0.5)
        except Exception as e:
            cpu_percpu = []
            cpu = None
            logging.warning(f"Could not retrieve CPU information: {e}")

        # Memory Information
        try:
            memory = psutil.virtual_memory()
            swap_memory = psutil.swap_memory()
        except Exception as e:
            memory = None
            swap_memory = None
            logging.warning(f"Could not retrieve memory information: {e}")

        # Disk Information
        try:
            disks = psutil.disk_partitions()
            disk_status = {}
            for d in disks:
                try:
                    detail = psutil.disk_usage(d.mountpoint)
                    disk_status[d.mountpoint] = {
                        "total": detail.total,
                        "used": detail.used,
                        "free": detail.free,
                        "percent": detail.percent
                    }
                except Exception as disk_e:
                    logging.warning(f"Could not retrieve disk information for {d.mountpoint}: {disk_e}")
        except Exception as e:
            disk_status = {}
            logging.warning(f"Could not retrieve disk partitions: {e}")

        # Network Information
        try:
            network = psutil.net_io_counters(pernic=True, nowrap=True)
            network_status = {}
            for interface, stats in network.items():
                network_status[interface] = {
                    "byte_sent": stats.bytes_sent,
                    "byte_recv": stats.bytes_recv
                }
        except Exception as e:
            network_status = {}
            logging.warning(f"Could not retrieve network information: {e}")

        # Process Information
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']):
                try:
                    processes.append({
                        "name": proc.info.get('name', 'Unknown'),
                        "command": " ".join(proc.info.get('cmdline', [])),
                        "pid": proc.info.get('pid'),
                        "cpu_percent": proc.info.get('cpu_percent'),
                        "memory_percent": proc.info.get('memory_percent')
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            # Sort and get top 10 processes
            cpu_top_10 = sorted(
                [p for p in processes if p['cpu_percent'] is not None], 
                key=lambda x: x['cpu_percent'], 
                reverse=True
            )[:10]

            memory_top_10 = sorted(
                [p for p in processes if p['memory_percent'] is not None], 
                key=lambda x: x['memory_percent'], 
                reverse=True
            )[:10]
        except Exception as e:
            cpu_top_10 = []
            memory_top_10 = []
            logging.warning(f"Could not retrieve process information: {e}")

        # Construct status dictionary
        status = {
            "cpu": {
                "cpu_percent": cpu,
                "cpu_percent_per_cpu": cpu_percpu,
            },
            "memory": {
                "virtual_memory": {
                    "total": memory.total if memory else None,
                    "available": memory.available if memory else None,
                    "percent": memory.percent if memory else None
                },
                "swap_memory": {
                    "total": swap_memory.total if swap_memory else None,
                    "used": swap_memory.used if swap_memory else None,
                    "percent": swap_memory.percent if swap_memory else None
                }
            },
            "disk": disk_status,
            "network": network_status,
            "process": {
                "cpu_top_10": cpu_top_10,
                "memory_top_10": memory_top_10
            }
        }
        
        return ResponseObject(data=status)

    except Exception as global_e:
        logging.error(f"Unexpected error in system status API: {global_e}")
        return ResponseObject(
            data={},
            error="Failed to retrieve system status",
            status_code=500
        )

@app.get(f'{APP_PREFIX}/')
def index():
    return render_template('index.html')

def backGroundThread():
    global WireguardConfigurations
    print(f"[WGDashboard] Background Thread #1 Started", flush=True)
    time.sleep(10)
    while True:
        with app.app_context():
            for c in WireguardConfigurations.values():
                if c.getStatus():
                    try:
                        c.getPeersTransfer()
                        c.getPeersLatestHandshake()
                        c.getPeersEndpoint()
                        c.getPeersList()
                        c.getRestrictedPeersList()
                    except Exception as e:
                        print(f"[WGDashboard] Background Thread #1 Error: {str(e)}", flush=True)
        time.sleep(10)

def peerJobScheduleBackgroundThread():
    with app.app_context():
        print(f"[WGDashboard] Background Thread #2 Started", flush=True)
        time.sleep(10)
        while True:
            AllPeerJobs.runJob()
            time.sleep(180)

def waitressInit():
    _, app_ip = DashboardConfig.GetConfig("Server", "app_ip")
    _, app_port = DashboardConfig.GetConfig("Server", "app_port")
    return app_ip, app_port

def InitWireguardConfigurationsList(startup: bool = False):
    confs = os.listdir(DashboardConfig.GetConfig("Server", "wg_conf_path")[1])
    confs.sort()
    for i in confs:
        if RegexMatch("^(.{1,}).(conf)$", i):
            i = i.replace('.conf', '')
            try:
                if i in WireguardConfigurations.keys():
                    if WireguardConfigurations[i].configurationFileChanged():
                        WireguardConfigurations[i] = Configuration(i)
                else:
                    WireguardConfigurations[i] = Configuration(i, startup=startup)
            except Configuration.InvalidConfigurationFileException as e:
                print(f"{i} have an invalid configuration file.")




AllPeerShareLinks: PeerShareLinks = PeerShareLinks()
AllPeerJobs: PeerJobs = PeerJobs()
JobLogger: PeerJobLogger = PeerJobLogger()
AllDashboardLogger: DashboardLogger = DashboardLogger()
_, app_ip = DashboardConfig.GetConfig("Server", "app_ip")
_, app_port = DashboardConfig.GetConfig("Server", "app_port")
_, WG_CONF_PATH = DashboardConfig.GetConfig("Server", "wg_conf_path")

WireguardConfigurations: dict[str, Configuration] = {}
InitWireguardConfigurationsList(startup=True)

def startThreads():
    bgThread = threading.Thread(target=backGroundThread)
    bgThread.daemon = True
    bgThread.start()
    
    scheduleJobThread = threading.Thread(target=peerJobScheduleBackgroundThread)
    scheduleJobThread.daemon = True
    scheduleJobThread.start()

def get_timestamped_filename():
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    return f'./log/access_{timestamp}.log'

@app.before_request
def before_request():
    """Store the start time of the request."""
    g.start_time = time.time()

@app.after_request
def after_request(response):
    """Log access details after the request is processed."""
    # Safeguard in case g.start_time is not set
    start_time = getattr(g, 'start_time', time.time())
    response_time = round((time.time() - start_time) * 1000, 2)  # in milliseconds
    
    # Format log entry
    timestamp = strftime('[%Y-%b-%d %H:%M]')
    log_entry = (
        f"{timestamp} "
        f"User-Agent: {request.user_agent.string} "
        f"IP: {request.remote_addr} "
        f"Referrer: {request.referrer or 'No Referrer'} "
        f"Method: {request.method} "
        f"Scheme: {request.scheme} "
        f"Path: {request.full_path} "
        f"Status: {response.status_code} "
        f"Response Time: {response_time} ms"
    )
    logger.info(log_entry)
    
    return response



# Fetch configurations




# Production Server using Waitress
if __name__ == "__main__":
   
    waitressInit()
    # Start background threads
    startThreads()

    # Initialize logger 
    # Set up the rotating file handler with dynamic filename
    log_filename = get_timestamped_filename()
    handler = RotatingFileHandler(log_filename, maxBytes=1000000, backupCount=3)

    logger = logging.getLogger('wiregate')
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)


    # Start the Waitress server with access logging enabled
    waitress.serve(
        app,
        host=app_ip,
        port=app_port,
        threads=8,
        _quiet=False,  # Ensures Waitress uses the 'waitress.access' logger for requests
    )

@app.post(f'{APP_PREFIX}/api/deleteConfigurationBackup')
def API_DeleteConfigurationBackup():
    try:
        data = request.get_json()
        if 'configurationName' not in data or 'backupFileName' not in data:
            return ResponseObject(False, "Missing required parameters")

        config_name = data['configurationName']
        backup_file = data['backupFileName']
        
        # Get backup paths
        backup_timestamp = backup_file.replace(f'{config_name}_', '').replace('.conf', '')
        backup_paths = get_backup_paths(config_name, backup_timestamp)
        
        # Delete backup files if they exist
        files_to_delete = [
            backup_paths['conf_file'],
            backup_paths['sql_file'],
            backup_paths['iptables_file']
        ]
        
        for file_path in files_to_delete:
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Check if config backup directory is empty and remove it if so
        if len(os.listdir(backup_paths['config_dir'])) == 0:
            os.rmdir(backup_paths['config_dir'])
            
        return ResponseObject(True, "Backup deleted successfully")
        
    except Exception as e:
        logging.error(f"Error deleting backup: {str(e)}")
        return ResponseObject(False, f"Failed to delete backup: {str(e)}")

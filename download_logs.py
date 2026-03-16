import os
import datetime
import paramiko
import stat
import requests

LOCAL_PATH = ""
SSH_TIMEOUT = 3
SERVERS = [
    # {
    #     'alias': 'COBALTSTRIKE',
    #     'hostname': '',
    #     'username': 'ubuntu',
    #     #'password': 'your_password',
    #     'key_filename': r'C:\Users\username\cert.pem',
    #     'pre_command': r'sudo rm -rf /home/ubuntu/logs && sudo cp -r /root/cobaltstrike/server/logs /home/ubuntu/logs',
    #     'remote_files': [
    #         '/home/ubuntu/logs',
    #     ],
    # },
    # {
    #     'alias': 'BRUTERATEL',
    #     'hostname': '',
    #     'username': 'ubuntu',
    #     #'password': 'your_password',
    #     'key_filename': r'C:\Users\username\cert.pem',
    #     'remote_files': [
    #         '/root/bruteratel/logs/',
    #     ],
    # },
    # {
    #    'alias': 'OC2',
    #    'hostname': '3.253.17.3',
    #    'username': 'ubuntu',
    #    #'password': 'your_password',
    #    'key_filename': r'C:\Users\username\cert.pem',
    #    'pre_command': r'sudo rm -rf /home/ubuntu/json && sudo cp -r /root/oc2/shared/logs/api/implant_logs/json /home/ubuntu/json',
    #    'remote_files': [
    #        '/home/ubuntu/json',      # ost logs json
    #        #'shared/logs/api/implant_logs/legacy_text',  # ost logs plain_text
    #    ],
    # },
    # {
    #     'alias': 'CUSTOMLOGS',
    #     'hostname': '',
    #     'username': 'ubuntu',
    #     #'password': 'your_password',
    #     'key_filename': r'C:\Users\username\cert.pem',
    #     'remote_files': [
    #         '/var/log/commandlog_c2.log',
    #     ],
    # },
    # {
    #    'alias': 'WEBSERVER',
    #    'hostname': '',
    #    'username': 'ubuntu',
    #    #'password': 'your_password',
    #    'key_filename': r'C:\Users\username\cert.pem',
    #    'remote_files': [
    #        '/var/log/apache2/access.log',      # Apache2 access log
    #        '/var/log/apache2/error.log',       # Apache2 error log (if required)
    #    ],
    # },
    
]

def getAlias(alias):
    parts = alias.rsplit(" - ", maxsplit=2)
    if len(parts) == 3:
        result = parts[-2] + " - " + parts[-1]
        return result.replace(" ", "")  # Output: S2 - Phishing Server 1
    else:
        return alias.replace(" ", "")
        

# Create a local folder with the current date (e.g., logs_2025-10-02)
today = datetime.date.today().strftime('%Y-%m-%d')
local_base_folder = os.path.join(LOCAL_PATH, f'logs_{today}')

# if not os.path.exists(local_base_folder):
#     os.makedirs(local_base_folder)

def retrieve_files(sftp, remote_path, local_path):
    normalized_remote = remote_path.rstrip('/') if remote_path != '/' else remote_path
    try:
        attrs = sftp.stat(normalized_remote)
    except FileNotFoundError:
        print(f"Remote path not found: {remote_path}")
        return

    if stat.S_ISDIR(attrs.st_mode):
        try:
            if os.path.exists(local_path) and not os.path.isdir(local_path):
                os.remove(local_path)
            os.makedirs(local_path, exist_ok=True)
            for entry in sftp.listdir_attr(normalized_remote):
                entry_remote = (
                    f"{normalized_remote}/{entry.filename}"
                    if normalized_remote != '/'
                    else f"/{entry.filename}"
                )
                entry_local = os.path.join(local_path, entry.filename)
                retrieve_files(sftp, entry_remote, entry_local)
        except Exception as e:
            print(f"Error retrieving directory {remote_path}: {e}")
    else:
        parent_dir = os.path.dirname(local_path) or local_path
        if os.path.exists(parent_dir) and not os.path.isdir(parent_dir):
            os.remove(parent_dir)
        os.makedirs(parent_dir, exist_ok=True)
        print(f"Downloading {normalized_remote} to {local_path}")
        sftp.get(normalized_remote, local_path)


def download_logs():
    for server in SERVERS:
        hostname = server['hostname']
        username = server['username']
        password = server.get('password')
        key_filename = server.get('key_filename')
        alias = getAlias(server['alias'])

        # Create a subfolder for each server to avoid collisions between files.
        server_folder = os.path.join(local_base_folder, alias)
        if not os.path.exists(server_folder):
            os.makedirs(server_folder)

        print(f"Connecting to server: {alias} ({hostname})")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sftp = None
        connect_kwargs = {
            'hostname': hostname,
            'username': username,
            'timeout': SSH_TIMEOUT,
            'banner_timeout': SSH_TIMEOUT,
            'auth_timeout': SSH_TIMEOUT,
        }
        try:
            if key_filename:
                ssh.connect(key_filename=key_filename, **connect_kwargs)
            else:
                ssh.connect(password=password, **connect_kwargs)

            stderr, stdout = None, None
            if 'pre_command' in server:
                print(f"Executing pre_command on {hostname}: {server['pre_command']}")
                stdin, stdout, stderr = ssh.exec_command(server['pre_command'].strip())
            
            if stderr:
                err = stderr.read().decode().strip()
                if err:
                    print(f"Error executing pre_command on {hostname}: {err} : {stdout.read().decode().strip()}")

            sftp = ssh.open_sftp()
            for remote_path in server['remote_files']:
                try:
                    normalized_remote = remote_path.rstrip('/') or remote_path
                    base_name = os.path.basename(normalized_remote) or 'root'
                    local_path = os.path.join(server_folder, base_name)
                    print(f"Syncing {remote_path} from {hostname} into {local_path}")
                    retrieve_files(sftp, remote_path, local_path)
                except Exception as ex:
                    print(f"Error downloading {remote_path} from {hostname}: {ex}")
        except Exception as ex:
            print(f"Connection failed for server {hostname}: {ex}")
        finally:
            if sftp is not None:
                sftp.close()
            ssh.close()

def main():
    download_logs()

if __name__ == '__main__':
    main()

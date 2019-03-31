"""
Module for gathering artifacts from filesystem:
- Deleted Company Data
- Modified Company Data
- Copied Company Data using TeamViewer
- Downloaded files analysis
"""

import datetime
import os
import struct
import requests
import time
from http.client import responses
from PMADB import add_action


# ------------ Deleted Company Data ----------------- #
def scan_recycle_bin(recycle_bin_path, company_folder_path):
    if os.path.isdir(recycle_bin_path):
        # instead of entering user if folder (cd S-1-5-21-3138777187-1060959929-2752825879-1000) I just crawl everything
        for root, dirs, files in os.walk(recycle_bin_path):
            for filename in files:
                if filename.startswith('$I'):
                    trashedfilepath = os.path.join(root, filename)
                    fi = open(trashedfilepath, 'rb')
                    results = read_dollar_i(fi)
                    fi.close()
                    if company_folder_path.replace('/', '\\') in results['file_path']:
                        msg = "Company data was deleted into Recycle Bin! ({})".format(results['file_path'])
                        # print(msg)
                        add_action(results['deleted_time'], 10, msg)


def parse_windows_filetime(date_value):
    # modified version of method from 'Python Digital Forensics Cookbook'
    microseconds = float(date_value) / 10
    ts = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=microseconds)
    return ts


def read_dollar_i(file_obj):
    # Originally from 'Python Digital Forensics Cookbook'
    # adapted not nu use Sleuth Kit read_random() but standard Python file read()
    # I ignore 8bytes of header and 8bytes representing deleted file size.
    header = file_obj.read(8)
    raw_file_size = struct.unpack('<q', file_obj.read(8))
    raw_deleted_time = struct.unpack('<q', file_obj.read(8))
    raw_file_path = file_obj.read(520)
    deleted_time = parse_windows_filetime(raw_deleted_time[0])
    file_path = str(raw_file_path.decode("utf16").strip("\x00"))[2:]
    return {'file_path': file_path, 'deleted_time': deleted_time}


# ------------ Modified Company Data ----------------- #

def scan_for_modifications(classified_data_folder):
    # warning: linux does not report proper creation time, but attribute change.
    # so we assume our company data have both times the same and we'll spot any modification comparing them
    for root, dirs, files in os.walk(classified_data_folder):
        for filename in files:
            path = os.path.join(root, filename)
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            ctime = datetime.datetime.fromtimestamp(os.path.getctime(path))
            if ctime != mtime:
                msg = "Company classified file {} modified!".format(filename)
                # print(msg)
                add_action(mtime, 11, msg)


# ------------ Copied Company Data using TeamViewer ----------------- #

def scan_for_copy_in_team_viewer(logfile, classified_data_folder):
    # TODO: take any *_Logfile.log files in that dir if exists
    if os.path.exists(logfile):
        with open(logfile, 'r') as logf:
            for line in logf.readlines():
                fldr = str(classified_data_folder).replace('/', '\\')
                if fldr in line:
                    parts = line.split()
                    timestamp = datetime.strptime(parts[0], '%a %b %d %H:%M:%S %Y')
                    add_action(timestamp, 6, "File copied using TeamViewer: {}".format(line))
    else:
        print("TeamViewer log not present.")

# ------------ Downloaded files analysis ----------------- #

def send_file_2_virustotal(filename, filepath, API_KEY):
    time.sleep(0.3)  # for time limitation of public api
    print('* Sending {} to VirusTotal:'.format(filename))
    params = {'apikey': API_KEY}
    files = {'file': (filename, open(filepath, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    json_response = response.json()
    # print(json_response)
    return json_response


def query_virustotal_4_report(API_KEY, resource):
    time.sleep(0.3)  # for time limitation of public api
    # TODO: query API in loop until results are there or introduce multithreading
    params = {'apikey': API_KEY, 'resource': resource}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  24hourForensics by Panagiotis Krommydakis"
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                            params=params, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        # print(responses[response.status_code])
        return None


def beautify_positives(scan_list):
    """Extract names of AVs and their responses for positive hits"""
    result = {}
    for name, contents in scan_list.items():
        if contents['detected']:
            result[name] = contents['result']
    return str(result)


def downloads_analysis(download_folder, API_KEY):
    """
    Uploading all files from Download folder to VirusTotal server for scanning
    and querying for scan results as described in
    https://www.virustotal.com/pl/documentation/public-api/
    and storing potentially malicious results in PMA_DB
    """

    cnt = 0
    for root, dirs, files in os.walk(download_folder):
        for filename in files:
            cnt += 1
    print("{} files will be scanned.".format(cnt))
    for root, dirs, files in os.walk(download_folder):
        for filename in files:
            cnt -= 1
            filepath = os.path.join(root, filename)
            ctime = os.path.getctime(filepath)  # maybe getmtime better on linux??
            timestamp = time.gmtime(ctime)
            fsize = os.path.getsize(filepath)
            if fsize < 32000000:  # public API has 32MB file size limit
                response = send_file_2_virustotal(filename, filepath, API_KEY)
                print('  {}:'.format(cnt) + response['verbose_msg'])
                if response['response_code'] == 1:
                    response2 = query_virustotal_4_report(API_KEY, response['resource'])
                    if response2:
                        print(' ' + response2['verbose_msg'])
                        # TODO: implement sth for 'Scan request successfully queued, come back later for the report'
                        if 'positives' in response2:
                            if response2['positives'] == 0:
                                print(' Clean :)')
                            else:
                                print(' {} positives!'.format(response2['positives']))
                                av_res = beautify_positives(response2['scans'])
                                print(av_res)
                                if 'shell' in str(av_res).lower():
                                    add_action(timestamp, 7, "Bind Shell code found!")
                                elif 'backdoor' in str(av_res).lower():
                                    add_action(timestamp, 8, "Reverse Shell code found!")
                                else:
                                    add_action(timestamp, 12, "Downloaded file '{}' containing malware. ({})".format(filename, av_res))


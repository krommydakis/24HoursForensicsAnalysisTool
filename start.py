import os
from PMADB import create_indexes
from parse_evtx import parse_windows_events
from parse_webhistory import analyse_edge_history
from parse_webhistory import analyse_chrome_history
from parse_registry import is_regripper_installed, analyse_installed_software, analyse_usb_devices
from datetime import datetime
from parse_filesystem import scan_recycle_bin, scan_for_modifications, scan_for_copy_in_team_viewer, downloads_analysis

import configparser

# ###### LOAD CONFIG AND PERFORM BASIC ENVIRONMENT CHECKS ###### #
config = configparser.ConfigParser()
config.read('config.ini')

total_started = datetime.now()

# check if image is mounted
if os.path.isdir(config['DEFAULT']['IMAGE_PATH']):
    print("Image mounted at: {}".format(config['DEFAULT']['IMAGE_PATH']))
else:
    print('Image not mounted!!!. Folder "{}" does not exist!'.format(config['DEFAULT']['IMAGE_PATH']))
    exit(1)


# check ElasticSearch connection
try:
    print("Using ElasticSearch instance: {}:{}".format(config['ELASTIC_SEARCH']['HOST'], config['ELASTIC_SEARCH']['PORT']))
    create_indexes()
except:
    print('Unable to connect to ES instance {}:{}!!!'.format(config['ELASTIC_SEARCH']['HOST'], config['ELASTIC_SEARCH']['PORT']))
    exit(1)


# check the Company Folder existence
CDF = os.path.join(config['DEFAULT']['IMAGE_PATH'], "Users", config['DEFAULT']['SUSPECTED_USER'], config['DEFAULT']['CLASSIFIED_DATA_FOLDER'])
if os.path.isdir(CDF):
    print("Company Data in: {}".format(config['DEFAULT']['CLASSIFIED_DATA_FOLDER']))
else:
    print('Company Data Folder missing!!:{}'.format(CDF))


# check RegRipper presence
if is_regripper_installed():
    print('RegRipper tool version: {}\n\n'.format(is_regripper_installed()))
else:
    print('Unable to run RegRipper from {}!!! Majority of atrifacts will not be found!'.format(config['3RD_PARTY']['REGRIPPER_PATH']))
    exit(1)

###################################################################


###################################################################
# --------------- Analyse windows event logs  --------------- #
winlogs_path = config['DEFAULT']['IMAGE_PATH'] + '/Windows/System32/winevt/Logs/'

if os.path.exists(winlogs_path):
    print('Obtaining Windows Logs from evtx files ... Be patient. This may take a while ...')
    started = datetime.now()
    parse_windows_events(winlogs_path, config['DEFAULT']['SUSPECTED_USER'])
    ended = datetime.now()
    duration = ended - started
    print("Finished processing Event logs in {} seconds.".format(duration.seconds))
else:
    print('Missing Windows Security Event Log Folder !?!?!?!')


# --------------- Analyse website history  --------------- #
USER_FOLDER = os.path.join(config['DEFAULT']['IMAGE_PATH'], "Users", config['DEFAULT']['SUSPECTED_USER'])
API_KEY = config['3RD_PARTY']['WEBSHRINKER_API_KEY']
API_SECRET = config['3RD_PARTY']['WEBSHRINKER_API_SECRET']
print('\nChecking Edge web browsing history...')
started = datetime.now()
analyse_edge_history(USER_FOLDER, API_KEY, API_SECRET)
ended = datetime.now()
duration = ended - started
print("... done in {} seconds.".format(duration.seconds))
print('\nChecking Chrome web browsing history...')
started = datetime.now()
analyse_chrome_history(USER_FOLDER, API_KEY, API_SECRET)
ended = datetime.now()
duration = ended - started
print("... done in {} seconds.".format(duration.seconds))


# --------------- Analyse registry hives --------------- #

# installation of software:
analyse_installed_software()

# USB usage
analyse_usb_devices()

# --------------- Analyse file system --------------- #

print("\nAnalyzing downloaded files...")
Down = os.path.join(config['DEFAULT']['IMAGE_PATH'], "Users", config['DEFAULT']['SUSPECTED_USER'], "Downloads")
if os.path.isdir(Down):
    started = datetime.now()
    # use virustotal api to categorize the file
    downloads_analysis(Down, config['3RD_PARTY']['VIRUSTOTAL_API_KEY'])
    ended = datetime.now()
    duration = ended - started
    print("... done in {} seconds.".format(duration.seconds))
else:
    print("Downloads folder is missing!!!")


# parse TeamViewer log file:
logfile = os.path.join(config['DEFAULT']['IMAGE_PATH'], "Program Files (x86)", "TeamViewer", "TeamViewer14_Logfile.log")
classified_data_folder = config['DEFAULT']["CLASSIFIED_DATA_FOLDER"]
scan_for_copy_in_team_viewer(logfile, classified_data_folder)

# find deleted files
recycle_bin_path = os.path.join(config['DEFAULT']['IMAGE_PATH'], "$Recycle.Bin")
if os.path.exists(recycle_bin_path):
    scan_recycle_bin(recycle_bin_path, config['DEFAULT']['CLASSIFIED_DATA_FOLDER'])
else:
    print('There is no Recycle Bin')


# find modified files
CDF = os.path.join(config['DEFAULT']['IMAGE_PATH'], "Users", config['DEFAULT']['SUSPECTED_USER'], config['DEFAULT']['CLASSIFIED_DATA_FOLDER'])
if os.path.isdir(CDF):
    scan_for_modifications(CDF)
else:
    print('Company Data Folder missing!!:{}'.format(CDF))


total_ended = datetime.now()
total_duration = total_ended - total_started

print("Scanning of image ({}) finished in {} seconds.\nPlease launch GUI to see result analysis.".format(config['DEFAULT']['IMAGE_PATH'], total_duration.seconds))

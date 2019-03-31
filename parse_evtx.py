import Evtx.Evtx as evtx
import Evtx.Views as e_views  # pip install python-evtx
import xmltodict
from datetime import datetime, time, timedelta
from PMADB import add_action
import os
import configparser


def parse_windows_events(winlogs_path, user):
    security_log = 'Security.evtx'
    # alternative???? : logon_log = 'Microsoft-Windows-Winlogon%4Operational.evtx'
    defender_log = 'Microsoft-Windows-Windows Defender%4Operational.evtx'
    print_log = 'Microsoft-Windows-PrintService%4Operational.evtx'
    winlogfile = winlogs_path + security_log
    defenderlogfile = winlogs_path + defender_log
    printlogfile =  winlogs_path + print_log

    parse_security_events(winlogfile, user)

    parse_defender_logs(defenderlogfile)

    if os.path.exists(printlogfile):
        parse_print_logs(printlogfile)


def evtx_2_json(evtx_file_path):
    xml_event_log = ''
    with evtx.Evtx(evtx_file_path) as log:
        xml_event_log += e_views.XML_HEADER
        xml_event_log += "<Events>"
        for record in log.records():
            event = record.xml()
            xml_event_log += event.replace(" xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"", "")
        xml_event_log += "</Events>"

    # print('Saving results as temporary XML...')
    # with open("event_log_tmp.xml", "w") as text_file:
    #     text_file.write(xml_event_log)

    event_log = xmltodict.parse(xml_event_log)

    # print('Saving results as temporary JSON...')
    # with open("event_log_tmp.json", "w") as jsonlog:
    #     j = json.dumps(event_log)
    #     jsonlog.write(j)

    # fix the date time in the dict and json alignment
    for event in event_log['Events']['Event']:
        timestamplen = len(event['System']['TimeCreated']['@SystemTime'])
        if timestamplen == 19:
            datetime_object = datetime.strptime(event['System']['TimeCreated']['@SystemTime'], '%Y-%m-%d %H:%M:%S')
            event['System']['TimeCreated'] = datetime_object
        if timestamplen == 26:
            datetime_object = datetime.strptime(event['System']['TimeCreated']['@SystemTime'], '%Y-%m-%d %H:%M:%S.%f')
            event['System']['TimeCreated'] = datetime_object

        fixed_data_dict = {}
        try:
            for ed in event['EventData']['Data']:
                if len(ed) == 2:
                    fixed_data_dict[ed['@Name']] = ed['#text']
            event['EventData'] = fixed_data_dict
        except (TypeError, KeyError):
            pass
    return event_log


def parse_security_events(winlogfile, user):
    event_log = evtx_2_json(winlogfile)

    # print('Saving results to ElasticSearch...')
    for event in event_log['Events']['Event']:
        # We could index all possible events with their entire body for future analysis with sth like:
        # idxstat = es.index(index='events_security_raw', doc_type='events', id=i, body=event)
        EventID = event['System']['EventID']['#text']
        if EventID == '4624':
            luser = event['EventData']['TargetUserName']
            timestmp = event['System']['TimeCreated']
            LogonType = event['EventData']['LogonType']
            logon_type_msg = ""
            if LogonType == '2':
                logon_type_msg = "Logon at keyboard and screen of system."
            if LogonType == '7':
                logon_type_msg = "Unlock (i.e. after screen saver)"
            if LogonType == '10':
                logon_type_msg = "Remote Logon."
            if luser == user:
                if timestmp.weekday() < 5:
                    start = time(8, 30)
                    end = time(17, 30)
                    if start <= timestmp.time() <= end:
                        # print("User {} logged during normal working hours. {}".format(luser, logon_type_msg))
                        add_action(timestmp, 0, msg)
                    else:
                        msg = "User {} logged after working hours! {}".format(luser, logon_type_msg)
                        # print(msg)
                        add_action(timestmp, 1, msg)
                else:
                    msg = "User {} logged outside working days! {}".format(luser, logon_type_msg)
                    # print(msg)
                    add_action(timestmp, 2, msg)
        if EventID == "1102":
            dtimestmp = event['System']['TimeCreated']
            msg = "Some of the Windows Logs got deleted!"
            print(msg)
            add_action(dtimestmp, 15, msg)
        if EventID == "4698":
            timestmp = event['System']['TimeCreated']
            msg = "A scheduled task was created!"
            #print(msg)
            add_action(timestmp, 22, msg)
        if EventID == "5140": # TODO: to be tested!!!
            timestmp = event['System']['TimeCreated']
            user = event['EventData']['ShareName']
            msg = "A notwork share was accessed!"
            #print(msg)
            add_action(timestmp, 17, msg)

        if EventID == "4802":
            timestmp: datetime = event['System']['TimeCreated']
            msg = "Screensaver invoked"
            #print(msg)
            add_action(timestmp, 25, msg)
            scr_started = timestmp
        if EventID == "4803":
            timestmp: datetime = event['System']['TimeCreated']
            msg = "Screensaver dismissed"
            #print(msg)
            add_action(timestmp, -25, msg)
            scr_ended = timestmp
            if scr_started.day == scr_ended.day:
                duration = scr_ended - scr_started
                if duration.seconds < 60*60*8:
                    #msg = "Screensaver was on for {} seconds.".format(duration.seconds)
                    timepoint = scr_started
                    for s in range(duration.seconds):
                        msg = "Screensaver second {} of {}".format(s, duration.seconds)
                        timepoint = timepoint + timedelta(seconds=1)
                        add_action(timepoint, 2500, msg)


def parse_defender_logs(defender_log_file_path):
    event_log = evtx_2_json(defender_log_file_path)
    for event in event_log['Events']['Event']:
        EventID = event['System']['EventID']['#text']
        timestmp = event['System']['TimeCreated']
        if EventID == "1102":
            msg = "Windows Logs got deleted!"
            #print(msg)
            add_action(timestmp, 15, msg)
        msg = None
        if EventID == '5001':
            msg = 'Real-time protection is disabled.'
        if EventID == '5010':
            msg = 'Scanning for malware and other potentially unwanted software is disabled.'
        if EventID == '5012':
            msg = 'Scanning for viruses is disabled.'
        if EventID == '1013':
            msg = 'The antimalware platform deleted history of malware and other potentially'
        if msg:
            add_action(timestmp, 14, msg)


def parse_print_logs(print_log_file_path):
    event_log = evtx_2_json(print_log_file_path)
    for event in event_log['Events']['Event']:
        EventID = event['System']['EventID']['#text']
        timestmp = event['System']['TimeCreated']
        if EventID == '307':
            user = event['UserData']['DocumentPrinted']['Param3']
            document = event['UserData']['DocumentPrinted']['Param2']
            msg = "User {} printed {}".format(user, document)
            add_action(timestmp, 21, msg)


if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('config.ini')
    paf = config['DEFAULT']['IMAGE_PATH'] + '/Windows/System32/winevt/Logs/Security.evtx'
    parse_security_events(paf, config['DEFAULT']['SUSPECTED_USER'])

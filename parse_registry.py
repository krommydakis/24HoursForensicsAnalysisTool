"""
Module for gathering artifacts from registry:
- Installed software
- USB usage
"""

import os
import subprocess
from datetime import datetime
from PMADB import add_software, add_action
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

hives = {
    "NTUSER.DAT": "/Users/{}/NTUSER.DAT".format(config['DEFAULT']['SUSPECTED_USER']),
    "SAM": "/Windows/System32/config/SAM",
    "SECURITY": "/Windows/System32/config/SECURITY",
    "SOFTWARE": "/Windows/System32/config/SOFTWARE",
    "SYSTEM": "/Windows/System32/config/SYSTEM"
}


def is_regripper_installed():
    out = str(subprocess.check_output([config['3RD_PARTY']['REGRIPPER_PATH'], '-h']))
    v = out.replace('\\n', '\n').splitlines()[1]
    ver = v.replace(" - CLI RegRipper tool\\t", "")
    return ver


def analyse_installed_software():
    #
    # Could manually iterate over HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
    # and reconstruct DisplayName, DisplayVersion, Publisher, InstallDate
    # but there is a listsoft module for RegRipper :)
    #
    hive = config['DEFAULT']['IMAGE_PATH'] + hives['NTUSER.DAT']
    if os.path.exists(hive):
        cmd = [config['3RD_PARTY']['REGRIPPER_PATH'], "-p", "listsoft", "-r", hive]
        # print(' '.join(cmd))
        out = subprocess.check_output(cmd)
        out = str(out)
        for line in out.split("\\n"):
            if "\\t" in line:
                timestamp, appname = line.split("\\t")
                installtime = datetime.strptime(timestamp, '%a %b %d %H:%M:%S %YZ ')
                # print("{} installed on {}".format(appname, installtime))
                add_software(installtime, appname)
    else:
        print('Could not find NTUSER.DAT hive ({})!!!'.format(hive))


def analyse_usb_devices():
    #
    # Could manually iterate over SYSTEM\CurrentControlSet\Enum\USBSTOR (src: SANS Poster)
    # but there is a usbstor3 module for RegRipper :)
    #
    hive = config['DEFAULT']['IMAGE_PATH'] + hives['SYSTEM']
    if os.path.exists(hive):
        cmd = [config['3RD_PARTY']['REGRIPPER_PATH'], "-p", "usbstor3", "-r", hive]
        # print(' '.join(cmd))
        out = subprocess.check_output(cmd)
        out = str(out)
        for line in out.split("\\n"):
            if "," in line:
                Name, LastWrite1, SN, LastWrite2, FriendlyName, nothing = line.split(",")
                LastWriteTime = datetime.strptime(LastWrite2, '%a %b %d %H:%M:%S %Y')
                msg = "User wrote to USB Device: {} (S/N:{})".format(FriendlyName, SN)
                add_action(LastWriteTime, 3, msg)

    else:
        print('Could not find SYSTEM hive ({})!!!'.format(hive))


if __name__ == "__main__":
    print(is_regripper_installed())

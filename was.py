__description__ = 'WAS - Wait A Sec: tool for scanning every file contained in a USB drive for malware before opening. Trust nobody.'
__author__ = 'Fabio Baroni <fabio@pentest.guru> @Fabiothebest89'
__version__ = '1.0.0'
__date__ = '13/09/2016'

'''
HISTORY:

6/8/2016 start of the project, media detection function
8/8/2016 added file hashing function
10/8/2016 added Virus Total result retrieval function
12/8/2016 added Virus Total result parsing and console notification
14/8/2016 added functionality to save results as a CSV file
16/8/2016 added audio notification in Italian and English language
13/9/2016 version 1.0.0 publicly released

TODO:
- add support for more languages
- implement file-locking function
- implement file upload function for scanning files not already scanned by Virus Total
- create Windows binary for ease of use by Windows folks
- add Linux support
'''

import win32api
import win32con
import win32gui
import hashlib
import os
from ctypes import *
import requests
import csv
import json
import time
import datetime
import configparser # import ConfigParser if you are using Python 2
import pyglet

script_dir = os.path.dirname(__file__)
# read configuration file
config = configparser.ConfigParser()
config.read("was-config.ini")
api = config.get("VIRUS-TOTAL", "api-key")
lang = config.get("NOTIFICATIONS", "lang")
audio = config.get("NOTIFICATIONS", "audio")
lock = config.get("FILE-LOCKING", "lock")
# EN sounds
device_scanning = pyglet.media.load(script_dir + '/audio/device_scanning.mp3')
virus_en = pyglet.media.load(script_dir + '/audio/virus_en.mp3')
# IT sounds
dispositivo_scansione = pyglet.media.load(script_dir + '/audio/dispositivo_scansione.mp3')
virus_it = pyglet.media.load(script_dir + '/audio/virus_it.mp3')
#
# Device change events (WM_DEVICECHANGE wParam)
#
DBT_DEVICEARRIVAL = 0x8000
DBT_DEVICEQUERYREMOVE = 0x8001
DBT_DEVICEQUERYREMOVEFAILED = 0x8002
DBT_DEVICEMOVEPENDING = 0x8003
DBT_DEVICEREMOVECOMPLETE = 0x8004
DBT_DEVICETYPESSPECIFIC = 0x8005
DBT_CONFIGCHANGED = 0x0018

#
# type of device in DEV_BROADCAST_HDR
#
DBT_DEVTYP_OEM = 0x00000000
DBT_DEVTYP_DEVNODE = 0x00000001
DBT_DEVTYP_VOLUME = 0x00000002
DBT_DEVTYPE_PORT = 0x00000003
DBT_DEVTYPE_NET = 0x00000004

#
# media types in DBT_DEVTYP_VOLUME
#
DBTF_MEDIA = 0x0001
DBTF_NET = 0x0002

WORD = c_ushort
DWORD = c_ulong


class DEV_BROADCAST_HDR(Structure):
    _fields_ = [
        ("dbch_size", DWORD),
        ("dbch_devicetype", DWORD),
        ("dbch_reserved", DWORD)
    ]


class DEV_BROADCAST_VOLUME(Structure):
    _fields_ = [
        ("dbcv_size", DWORD),
        ("dbcv_devicetype", DWORD),
        ("dbcv_reserved", DWORD),
        ("dbcv_unitmask", DWORD),
        ("dbcv_flags", WORD)
    ]


def drive_from_mask(mask):
    n_drive = 0
    while 1:
        if (mask & (2 ** n_drive)):
            return n_drive
        else:
            n_drive += 1

def retrieve_vt_report(filename, md5, hashes):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    global api
    global lang
    global audio
    global lock
    count = 1
    to_scan = []
    i = datetime.datetime.now()
    file_to_open = "{day}-{month}-{year}_{hour}-{minute}_malware_scan.csv".format(day = i.day, month = i.month, year = i.year, hour = i.hour, minute = i.minute)
    headers = ["filename", "md5", "positives", "permalink"]
    with open(file_to_open, "a") as f:
        f_csv = csv.writer(f)
        f_csv.writerow(headers)
        for file_hash in md5:
            params = {"apikey": api, "resource": file_hash}
            r = requests.post(url, data=params)
            if r.status_code == requests.codes.ALL_OK:
                report = json.loads(r.text)
                print(report)
                print(report['response_code'])
                if report['response_code'] == 0:
                    to_scan.append(file_hash)
                else:
                    positives = report['positives']
                    if positives != 0:
                        if audio == "ON" and lang == "EN":
                            virus_en.play()
                        elif audio =="ON" and lang == "IT":
                            virus_it.play()
                        else:
                            pass
                        permalink = report['permalink']
                        for x, y in iter(hashes.items()):
                            if y == file_hash:
                                name = x
                        row = [name, file_hash, positives, permalink]
                        f_csv.writerow(row)
            if count % 4 == 0:  # sleeps in order to ensure a max of 4 requests/min in accordance to the public API limit
                time.sleep(60)
                count += 1
    os.startfile(file_to_open)

def md5_files(path, blocksize = 2**20):
    hashes = {}
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            print(file_path)
            with open(file_path, "rb") as f:
                data = f.read(blocksize)
                hasher = hashlib.md5(data) # it's important to create a new MD5 object for every file
                while data:
                    data = f.read(blocksize)
                    hasher.update(data)
                    hashes[file_path] = hasher.hexdigest()
    if hashes:
        retrieve_vt_report(list(hashes.keys()), list(hashes.values()), hashes)
    return hashes


class Notification:
    def __init__(self):
        message_map = {
            win32con.WM_DEVICECHANGE: self.onDeviceChange
        }

        wc = win32gui.WNDCLASS()
        hinst = wc.hInstance = win32api.GetModuleHandle(None)
        wc.lpszClassName = "DeviceChangeDemo"
        wc.style = win32con.CS_VREDRAW | win32con.CS_HREDRAW
        wc.hCursor = win32gui.LoadCursor(0, win32con.IDC_ARROW)
        wc.hbrBackground = win32con.COLOR_WINDOW
        wc.lpfnWndProc = message_map
        classAtom = win32gui.RegisterClass(wc)
        style = win32con.WS_OVERLAPPED | win32con.WS_SYSMENU
        self.hwnd = win32gui.CreateWindow(
            classAtom,
            "Device Change Demo",
            style,
            0, 0,
            win32con.CW_USEDEFAULT, win32con.CW_USEDEFAULT,
            0, 0,
            hinst, None
        )

    def onDeviceChange(self, hwnd, msg, wparam, lparam):
        #
        # WM_DEVICECHANGE:
        #  wParam - type of change: arrival, removal etc.
        #  lParam - what's changed?
        #    if it's a volume then...
        #  lParam - what's changed more exactly
        #
        dev_broadcast_hdr = DEV_BROADCAST_HDR.from_address(lparam)
        global audio
        global lang

        if wparam == DBT_DEVICEARRIVAL:
            if dev_broadcast_hdr.dbch_devicetype == DBT_DEVTYP_VOLUME:
                if audio == "ON" and lang == "EN":
                    device_scanning.play()
                elif audio == "ON" and lang == "IT":
                    dispositivo_scansione.play()
                else:
                    pass

                dev_broadcast_volume = DEV_BROADCAST_VOLUME.from_address(lparam)
                drive_letter_bit = drive_from_mask(dev_broadcast_volume.dbcv_unitmask)
                drive_letter = chr(ord("A") + drive_letter_bit)
                letter_addendum = ":\\"
                drive_letter_path = "".join([drive_letter, letter_addendum])
                print(drive_letter_path)
                md5_files(drive_letter_path)


        return 1

if __name__ == '__main__':
    w = Notification()
    win32gui.PumpMessages()

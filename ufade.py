#!/usr/bin/env python3
# UFADE - Universal Forensic Apple Device Extractor (c) C.Peter 2024
# Licensed under GPLv3 License
from pymobiledevice3 import usbmux, exceptions, lockdown
from pymobiledevice3.services.mobile_image_mounter import DeveloperDiskImageMounter, MobileImageMounterService, PersonalizedImageMounter
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services import installation_proxy
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
from pymobiledevice3.services.springboard import SpringBoardServicesService
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.crash_reports import CrashReportsManager
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
from pymobiledevice3.services.screenshot import ScreenshotService  
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.amfi import AmfiService
from dialog import Dialog
from iOSbackup import iOSbackup
from pyiosbackup import Backup
from datetime import datetime, timedelta, timezone
from curses import wrapper
import contextlib
import pandas as pd
import numpy as np
import tarfile
import zipfile
import locale
import shutil
import os
import sys
import re
import string
import plistlib
import hashlib
import beepy
import threading
import curses
import time


locale.setlocale(locale.LC_ALL, '')

d = Dialog(dialog="dialog")
d.set_background_title("Universal Forensic Apple Device Extractor (UFADE) by Prosch")
pw = '12345'

# Check for Apple device #
def check_device():
    try:
        device = usbmux.select_device()
        lockdown = create_using_usbmux()
        
    except:
        code = d.yesno("No Apple device found! Check again?")
        if code == d.OK:
            check_device()
        else:
            raise SystemExit

    finally:
        try: 
            lockdown = create_using_usbmux()
            return(lockdown)
        except: 
            pass
        
    
#Menu options
def select_menu(main_screen):
    code, tag = d.menu("Choose:",
    choices=[("(1)", "Save device information to text", "Save device information and a list of user-installed apps to a textfile"),
             ("(2)", "Logical (iTunes-Style) Backup", "Perform a backup as iTunes would do it."),
             ("(3)", "Logical+ Backup", "Perform and decrypt an iTunes backup, gather AFC-media files, shared App folders and crash reports."),
             ("(4)", "Logical+ Backup (UFED-Style)", "Creates an advanced Logical Backup as ZIP with an UFD File for PA."),
             ("(5)", "Collect Unified Logs", "Collects the AUL from the device and saves them as a logarchive."),
             ("(6)", "Developer Options", "Access developer mode for further options.(< iOS 17)")],
             item_help=True, title=(dev_name + ", iOS " + version))
    if code == d.OK:
        if tag == "(1)":
            save_info_menu()
        elif tag == "(2)":
            perf_itunes()
        elif tag == "(3)":
            perf_logical_plus(None)
        elif tag == "(4)":
            perf_logical_plus("UFED")
        elif tag == "(5)":
            collect_ul()
        elif tag == "(6)":
            developer_options()
        else:
            sys.exit()
    else:
        sys.exit()

#Set directory
def chdir():
    dir = os.getcwd()
    code = d.yesno("Current working directory is: " + dir + "\n\nChange directory?")
    if code == d.OK:
        code, user_input = d.inputbox("Enter the name of the new directory:", title="New Path")
        if code == d.OK:
            try:
                if user_input == '':
                    user_input = '.'
                os.chdir(user_input)
                dir = os.getcwd()
                d.msgbox("New working directory is: " + dir)
                pass
            except:
                os.mkdir(user_input)
                os.chdir(user_input)
                dir = os.getcwd()
                d.msgbox("New working directory is: " + dir)
        else:
            d.msgbox("Working directory hasn't changed")
            pass
    else:
        pass
    return(dir)

# Check if a device is connected and print info
def show_device():
        d.msgbox("Device found: \n\n" + 
        "Model-Nr: " + dev_name + 
        "\nDev-Name: " + name +
        "\nHardware: " + hardware + ", " + mnr + 
        "\nProduct : " + product +
        "\nSoftware: " + version +
        "\nBuild-Nr: " + build +
        "\nLanguage: " + language +
        "\nSerialnr: " + snr +
        "\nMLB-snr : " + mlbsnr +
        "\nWifi MAC: " + w_mac +
        "\nBT - MAC: " + b_mac +
        "\nDisk Use: " + graph_progress +
        "\nCapacity: " + disk + "0 GB" +
        "\nUsed Cap: " + used + " GB" +
        "\nFree Cap: " + free + " GB" +  
        "\nUDID : " + udid + 
        "\nECID : " + ecid +
        "\nIMEI : " + imei +
        "\nIMEI2: " + imei2, height=26, width=52)

#Play a notfication sound:
def notify():
    beepy.beep(1)
    curses.flash()
    time.sleep(1)

#Save device information to txt File
def save_info():
    file = open("device_" + udid + ".txt", "w")
    file.write("## DEVICE ##\n\n" + "Model-Nr:   " + dev_name + "\nDev-Name:   " + name + "\nHardware:   " + hardware + ", " + mnr + "\nProduct:    " + product +
        "\nSoftware:   " + version + "\nBuild-Nr:   " + build + "\nLanguage:   " + language + "\nSerialnr:   " + snr + "\nMLB-snr:    " + mlbsnr +
        "\nWifi MAC:   " + w_mac + "\nBT-MAC:     " + b_mac + "\nCapacity:   " + disk + "0 GB" + "\nFree Space: " + free + " GB" +
        "\nUDID :      " + udid + "\nECID :      " + ecid + "\nIMEI :      " + imei + "\nIMEI2:      " + imei2 + "\n\n" + "## Installed Apps (by user) [App, shared documents] ## \n")
    #Save user-installed Apps to txt
    try: l = str(len(max(app_id_list, key=len)))  
    except: l = 40 
    #for app in app_doc_list:
    for app in app_id_list:
        try: 
            apps.get(app)['UIFileSharingEnabled']
            sharing = 'yes'
        except:
            sharing = 'no'
        file.write("\n" + '{:{l}}'.format(app, l=l) + "\t [" + sharing + "]")
    file.close()

#Create the info-file as txt
def save_info_menu():
    save_info()
    d.msgbox("Info written to device_" + udid + ".txt")
    wrapper(select_menu)

#Stop the beep-timer for the PIN promt and show the backup process
def process_beep(x,m, beep_timer):
    beep_timer.cancel()
    d.gauge_update(int(x),"Performing " + m + " Backup: ",update_text=True)

#Perform iTunes Backup
def iTunes_bu(mode):
    #screen = curses.initscr()
    m = mode
    pw_found = 0

    #Check for active Encryption and activate
    try:
        beep_timer = threading.Timer(13.0,notify)                                                                           
        beep_timer.start()
        curses.noecho()
        d.infobox("Checking Backup Encryption.\n\nUnlock device with PIN/PW if prompted")                                   
        curses.echo()            
        c1 = str(Mobilebackup2Service(lockdown).change_password(new="12345"))                                                #Try to activate backup encryption with password "12345"
        if c1 == "None":
            beep_timer.cancel()
        d.infobox("New Backup password: \"12345\" \n\nStarting Backup...\n\nUnlock device with PIN/PW")
        pw_found = 1            
        
    except:
        beep_timer.cancel()
        code = d.yesno("Backup Encryption is activated with password. Is the password known?")                                 
        if code == d.OK:
            code, user_input = d.inputbox("Enter the password:", title="Backup password: ")                                 #Get the password from user input
            if code == d.OK:
                pw = user_input
                try: 
                    Mobilebackup2Service(lockdown).change_password(old=pw)                                                  #Try to deactivate backup encryption with the given password
                    pw_found = 1
                except: 
                    d.msgbox("Wrong password.")
                    pass
        else:
            code = d.yesno("Do you want to attemt a password bruteforce? (Disable PIN/PW on Device beforehand)")
            if code == d.OK:
                code = d.yesno("Do you want to use the provided dictionary?")
                if code == d.OK:
                        with open(os.path.dirname(__file__) + "/bu_pw.txt") as pwds:
                            pw_list = pwds.read().splitlines()
                            pw_count = len(pw_list) 
                else:
                    code, user_input = d.inputbox("Enter the path to your file:", title="Password File: ")
                    if code == d.OK:
                        try:
                            with open(user_input) as pwds:
                                pw_list = pwds.read().splitlines()
                                pw_count = len(pw_list)
                        except:
                            d.msgbox("Error loading file!")
                            pass
                    else:
                        wrapper(select_menu)

                pw_num = 0
                pw_pro = 0
                d.gauge_start("Bruteforcing backup password on device: ")
                for pw in pw_list:
                    d.gauge_update(pw_pro)                    
                    try: 
                        Mobilebackup2Service(lockdown).change_password(old=pw)
                        d.msgbox("Password found: " + pw)
                        pw_found = 1
                        break
                    except:
                        pass
                    pw_num += 1
                    pw_pro = int(100*(pw_num/pw_count))

                
                if pw_found == 0:        
                    code_reset = d.yesno("Dictionary exhausted. Do you want to reset the password on the device?")
                    if code_reset == d.OK:
                        icons = SpringBoardServicesService(lockdown).get_icon_state()
                        d.msgbox("Unlock the device. \nOpen the \"Settings\"-app \n--> \"General\" \n--> \"Reset\" (bottom) \n--> \"Reset all Settings\"\n\n"
                            + "You will loose known networks, user settings and dictionary. App and User-Data will remain.\n\nWait for the device to reboot and press \"OK\"", height=18, width=52)
                        
                        try:
                            beep_timer = threading.Timer(13.0,notify)
                            beep_timer.start()
                            d.infobox("Trying to activate Backup Encryption again. \n\nUnlock device with PIN/PW if prompted") 
                            c = str(Mobilebackup2Service(lockdown).change_password(new="12345"))
                            if c == 'None':
                                beep_timer.cancel() 
                            pw_found = 1
                            SpringBoardServicesService(lockdown).set_icon_state(icons)
                        except:
                            beep_timer.cancel()
                            d.msgbox("Uh-Oh ... An error was raised ... try again.")
                            pass
                    else:
                        pass
            
            else:
                d.msgbox("You are still able to create a backup: \nUnlock the device. \nOpen the \"Settings\"-app \n--> \"General\" \n--> \"Reset\" (bottom) \n--> \"Reset all Settings\"\n\n"
                            + "You will loose known networks, user settings and dictionary. App and User-Data will remain.\n\nWait for the device to reboot and start the extraction again.", height=18, width=52) 
                    

        if pw_found == 1:
            curses.noecho()                
            d.infobox("Encryption has to be reactivated\n\nNew Password is: \"12345\" \n\nUnlock device with PIN/PW if prompted")
            curses.echo()
            try:
                beep_timer = threading.Timer(13.0,notify)
                beep_timer.start() 
                c2 = str(Mobilebackup2Service(lockdown).change_password(new="12345"))
                if c2 == "None":
                    beep_timer.cancel()
            except: 
                beep_timer.cancel()
                pass
            d.infobox("Starting Backup...")

    finally:
        if pw_found == 1:
            d.gauge_start("Performing " + m + " Backup - Unlock device with PIN/PW if prompted")
            beep_timer = threading.Timer(13.0,notify)
            beep_timer.start()
            stderr_old = sys.stderr
            sys.stderr = None 
            curses.noecho()
            Mobilebackup2Service(lockdown).backup(full=True,  progress_callback=lambda x: (process_beep(x,m,beep_timer)))
            curses.echo()
            sys.stderr = stderr_old
            d.gauge_stop()
            save_info()
            beep_timer = threading.Timer(13.0,notify)
            beep_timer.start()
            curses.noecho()
            d.infobox("iTunes Backup complete! Trying to deactivate Backup Encryption again. \n\nUnlock device with PIN/PW if prompted")
            curses.echo() 
            c3 = str(Mobilebackup2Service(lockdown).change_password(old="12345"))
            if c3 == 'None':
                beep_timer.cancel()
        else:
            curses.endwin()
            wrapper(select_menu)

def perf_itunes():
    iTunes_bu("iTunes-Style")                                                                                               #call iTunes Backup with "iTunes-Style" written in dialog
    try: os.rename(udid, udid + "_iTunes")  
    except: pass                                                                                                            #rename backup folder to prevent conflicts with other workflow-options
    d.msgbox("Backup completed!")
    wrapper(select_menu)
    
#Make advanced Backup - l_type(t) defines the type: 'None' for regular; 'UFED' for UFED-Style
def perf_logical_plus(t):
    l_type = t
    #if int(version.split(".")[0]) < 10:
    #    d.msgbox("Not supported: \niOS " + version + " is not supported in this workflow.")
    #    wrapper(select_menu)
    #    raise SystemExit()
    try: os.mkdir(".tar_tmp")                                                                                               #create temp folder for files to zip/tar
    except: pass

    try: os.mkdir(".tar_tmp/itunes_bu")                                                                                     #create folder for decrypted backup
    except: pass
    now = datetime.now()
    iTunes_bu("Logical+")                                                                                                   #call iTunes Backup with "Logical+" written in dialog
    
    if l_type != "UFED":
        try:
            b = iOSbackup(udid=udid, cleartextpassword="12345", derivedkey=None, backuproot="./")                           #Load Backup with Password
            key = b.getDecryptionKey()                                                                                      #Get decryption Key
            b = iOSbackup(udid=udid, derivedkey=key, backuproot="./")                                                       #Load Backup again with Key
            backupfiles = pd.DataFrame(b.getBackupFilesList(), columns=['backupFile','domain','name','relativePath'])       #read dataframe from iOSbackup to pandas module
            line_list = []
            line_cnt = 0
            for line in backupfiles['relativePath']:                                                                        #get amount of lines (files) of backup
                if(line not in line_list):
                    line_cnt += 1
                    line_list.append(line)
            d_nr = 0
            d.gauge_start("Decrypting iTunes Backup: ")                                                                     #show percentage of decryption-process
            tar = tarfile.open(udid + "_logical_plus.tar", "w:")
            for file in line_list:
                d_nr += 1
                dpro = int(100*(d_nr/line_cnt)) 
                d.gauge_update(dpro)
                b.getFileDecryptedCopy(relativePath=file, targetName=file, targetFolder=".tar_tmp/itunes_bu")               #actually decrypt the backup-files
                file_path = os.path.join('.tar_tmp/itunes_bu', file)
                tar.add(file_path, arcname=os.path.join("iTunes_Backup/", 
                    backupfiles.loc[backupfiles['relativePath'] == file, 'domain'].iloc[0], file), recursive=False)         #add files to the TAR
                try: os.remove(file_path)                                                                                   #remove the file after adding
                except: pass    
            d.gauge_stop()
        except:                                                                                                             #use pyiosbackup as fallback for older devices (atm iOSbackup is behaving more reliable for newer iOS Versions)
            d.infobox("Decrypting iTunes Backup - this may take a while.")
            Backup.from_path(backup_path=udid, password="12345").unback(".tar_tmp/itunes_bu")
            tar = tarfile.open(udid + "_logical_plus.tar", "w:")
            tar.add(".tar_tmp/itunes_bu", arcname="iTunes_Backup/", recursive=True)

        shutil.rmtree(".tar_tmp/itunes_bu")                                                                                 #remove the backup folder
        shutil.rmtree(udid)
        
    else:
        zipname = "Apple_" + hardware.upper() + " " + dev_name + ".zip"                                                     #create ZIP-File for CLB PA (TAR-handling isn't as good here)
        zip = zipfile.ZipFile(zipname, "w")
        d.infobox("Processing Backup ...")
        base = udid
        for root, dirs, files in os.walk(base):
            for file in files:
                source_file = os.path.join(root, file)
                filename = os.path.relpath(source_file, base)
                zip.write(source_file, arcname=os.path.join("iPhoneDump/Backup Service", udid, "Snapshot", filename))       #just copy the encrypted backup to a ZIP
                
        shutil.rmtree(udid)                                                                                                 #delete the backup after zipping

    #Gather Media Directory
    media_list = []
    d.gauge_start("Performing AFC Extraction of Mediafiles")
    for line in AfcService(lockdown).listdir("/"):
            media_list.append(line)                                                                                         #get amount of lines (files and folders) in media root
    media_count = len(media_list)
    try: os.mkdir(".tar_tmp/media")
    except: pass
    m_nr = 0
    for entry in media_list:
        m_nr += 1
        mpro = int(100*(m_nr/media_count))
        d.gauge_update(mpro)
        try:
            AfcService(lockdown).pull(entry, ".tar_tmp/media/")
            file_path = os.path.join('.tar_tmp/media/', entry)                                                              #get the files and folders shared over AFC
            if l_type != "UFED":
                tar.add(file_path, arcname=os.path.join("Media/", entry), recursive=True)                                   #add the file/folder to the TAR
            else:
                if os.path.isfile(file_path):
                    zip.write(file_path, arcname=os.path.join("iPhoneDump/AFC Service/", entry))                            #add the file/folder to the ZIP
                elif os.path.isdir(file_path):
                    for root, dirs, files in os.walk(".tar_tmp/media"):
                        for file in files:
                            source_file = os.path.join(root, file)
                            filename = os.path.relpath(source_file, ".tar_tmp/media")
                            zip.write(source_file, arcname=os.path.join("iPhoneDump/AFC Service/", filename))
            try: os.remove(file_path)
            except: shutil.rmtree(file_path)
        except:
            pass
    d.gauge_stop()
    shutil.rmtree(".tar_tmp/media")                                                                                         #remove media-folder

    #Gather Shared App-Folders
    media_count = 0
    d.gauge_start("Performing Extraction of Shared App-Files")
    for app in doc_list:
        if app == 'yes':
            media_count += 1

    try: os.mkdir(".tar_tmp/app_doc")
    except: pass
    m_nr = 0
    i = 0
    for app in app_id_list:
        if doc_list[i] == 'yes':
            m_nr += 1
            mpro = int(100*(m_nr/media_count))
            d.gauge_update(mpro)
            file_path = os.path.join(".tar_tmp/app_doc/", app, str((apps.get(app)['EnvironmentVariables'])['CFFIXED_USER_HOME'])[1:], "Documents/")
            os.makedirs(file_path, exist_ok=True)
            HouseArrestService(lockdown, bundle_id=app, documents_only=True).pull("/Documents/.", file_path)
            if l_type != "UFED":
                tar.add(file_path, arcname=os.path.join("App_Share/", app, str((apps.get(app)['EnvironmentVariables'])['CFFIXED_USER_HOME'])[1:], "Documents/"), recursive=True)
            else:
                for root, dirs, files in os.walk(file_path):
                    for file in files:
                        source_file = os.path.join(root, file)
                        filename = os.path.relpath(source_file, file_path)
                        zip.write(source_file, arcname=os.path.join("iPhoneDump/Applications/", app, filename))
            try: os.remove(file_path)
            except: shutil.rmtree(file_path)
        i += 1
    d.gauge_stop()
    shutil.rmtree(".tar_tmp/app_doc")

    #Gather Crash-Reports
    if l_type != "UFED":
        crash_count = 0
        crash_list = []
        d.gauge_start("Performing Extraction of Crash Reports")
        for entry in CrashReportsManager(lockdown).ls(""):
            crash_list.append(entry)
            crash_count += 1           
        try: os.mkdir(".tar_tmp/Crash")
        except: pass
        c_nr = 0
        for entry in crash_list:
            c_nr += 1
            try: AfcService(lockdown, service_name="com.apple.crashreportcopymobile").pull(relative_src=entry, dst=".tar_tmp/Crash", src_dir="")
            except: pass
            cpro = int(100*(c_nr/crash_count))
            d.gauge_update(cpro)
        tar.add(".tar_tmp/Crash", arcname=("/Crash"), recursive=True)
        d.gauge_update(100)
        d.gauge_stop()
        shutil.rmtree(".tar_tmp/Crash")

        
    #Gather device information as device_values.plist for UFD-ZIP
    else:
        de_va1 = ["ActivationPublicKey", "ActivationState", "ActivationStateAcknowledged", "BasebandSerialNumber", "BasebandStatus", "BasebandVersion", "BluetoothAddress", "BuildVersion", "CPUArchitecture", "DeviceCertificate", 
                        "DeviceClass", "DeviceColor", "DeviceName", "DevicePublicKey", "DieID", "FirmwareVersion", "HardwareModel", "HardwarePlatform", "HostAttached", "InternationalMobileEquipmentIdentity", "MLBSerialNumber", 
                        "MobileSubscriberCountryCode", "MobileSubscriberNetworkCode", "ModelNumber", "PartitionType", "PasswordProtected", "ProductionSOC", "ProductType", "ProductVersion", "ProtocolVersion", "ProximitySensorCalibration", 
                        "RegionInfo", "SerialNumber", "SIMStatus", "SoftwareBehavior", "SoftwareBundleVersion", "SupportedDeviceFamilies", "TelephonyCapability", "TimeIntervalSince1970", "TimeZone", "TimeZoneOffsetFromUTC", 
                        "TrustedHostAttached", "UniqueChipID", "UniqueDeviceID", "UseRaptorCerts", "Uses24HourClock", "WiFiAddress" ]
        de_va2 = ["com.apple.disk_usage", "com.apple.disk_usage.factory","com.apple.fairplay", "com.apple.iTunes","com.apple.international", "com.apple.iqagent", "com.apple.mobile.backup",
                    "com.apple.mobile.battery", "com.apple.mobile.chaperone", "com.apple.mobile.data_sync", "com.apple.mobile.debug", "com.apple.mobile.iTunes", "com.apple.mobile.iTunes.SQLMusicLibraryPostProcessCommands", 
                    "com.apple.mobile.iTunes.accessories</key>", "com.apple.mobile.iTunes.store", "com.apple.mobile.internal", "com.apple.mobile.lockdown_cache", "com.apple.mobile.lockdownd",
                    "com.apple.mobile.mobile_application_usage", "com.apple.mobile.nikita", "com.apple.mobile.restriction", "com.apple.mobile.software_behavior", "com.apple.mobile.sync_data_class",
                    "com.apple.mobile.tethered_sync", "com.apple.mobile.third_party_termination", "com.apple.mobile.user_preferences", "com.apple.mobile.wireless_lockdown", "com.apple.purplebuddy", "com.apple.xcode.developerdomain"]
        de_va_di = {}
        de_va_di = {}
        for key in de_va1:
            try: de_va_di.update([(key,(lockdown.get_value("",key)))])
            except: pass
        for key in de_va2:
            try: de_va_di.update([(key,(lockdown.get_value(key,"")))])
            except: pass

        with open("device_values.plist", "wb") as file:
            plistlib.dump(de_va_di, file)
        
    #Begin Time for UFD-Report
        local_timezone = datetime.now(timezone.utc).astimezone().tzinfo
        utc_offset = now.astimezone().utcoffset()
        utc_offset_hours = utc_offset.total_seconds() / 3600
        if utc_offset_hours >= 0:
            sign = "+"
        else:
            sign = "-"
        output_format = "%d/%m/%Y %H:%M:%S" 
        begin = str(now.strftime(output_format)) + " (" + sign + str(int(utc_offset_hours)) + ")"

    #End Time for UFD-Report
        end = datetime.now()
        local_timezone = datetime.now(timezone.utc).astimezone().tzinfo
        utc_offset = end.astimezone().utcoffset()
        utc_offset_hours = utc_offset.total_seconds() / 3600
        if utc_offset_hours >= 0:
            sign = "+"
        else:
            sign = "-"
        output_format = "%d/%m/%Y %H:%M:%S" 
        e_end = str(end.strftime(output_format)) + " (" + sign + str(int(utc_offset_hours)) + ")"

        #Create the PhoneInfo.xml for the UFD-ZIP
        all_list = lockdown.get_value("","")
        dic_a = {'Request': 'GetValue', 'Value': all_list}
        with open("PhoneInfo.xml", "wb") as file:
            plistlib.dump(dic_a, file)
        zip.write("PhoneInfo.xml", arcname=("iPhoneDump/Lockdown Service/PhoneInfo.xml"))
        zip.write("device_values.plist", arcname=("iPhoneDump/Lockdown Service/device_values.plist"))
        os.remove("PhoneInfo.xml")
        os.remove("device_values.plist")
    shutil.rmtree(".tar_tmp/")
    
    if l_type != 'UFED':
        tar.close()
    else:
        zip.close()
        try:
            with open(zipname, 'rb', buffering=0) as z:
                z_hash = hashlib.file_digest(z, 'sha256').hexdigest()
        except:
            z_hash = " Error - Python >= 3.11 required"

        with open("Apple_" + hardware.upper() + " " + dev_name + ".ufd", "w") as ufdf:
            ufdf.write("[DeviceInfo]\nIMEI1=" + imei + "\nIMEI2=" + imei2 + "\nModel=" + product + "\nOS=" + version + "\nVendor=Apple\n\n[Dumps]\nFileDump=Apple_" + hardware.upper() + " " +
            dev_name + ".zip\n\n[ExtractionStatus]\nExtractionStatus=Success\n\n[FileDump]\nType=ZIPfolder\nZIPLogicalPath=iPhoneDump\n\n[General]\nAcquisitionTool=UFADE\nBackupPassword=12345\nConnectionType=Cable No. 210 or Original Cable\nDate=" + begin + "\nDevice=" + d_class.upper() + "\nEndTime=" + e_end + "\nExtractionNameFromXML=File System\nExtractionType=AdvancedLogical\nFullName=" +
            hardware.upper() + " " + dev_name + "\nGUID=" + udid + "\nInternalBuild=\nIsEncrypted=True\nIsEncryptedBySystem=True\nMachineName=\nModel=" + hardware.upper() + " " + dev_name + "\nUfdVer=1.2\nUnitId=\nUserName=\nVendor=Apple\nVersion=other\n\n[SHA256]\n" + zipname + "=" + z_hash.upper() + "")

    d.msgbox("Logical+ Backup completed!")
    wrapper(select_menu)

#Collect Unified Logs
def collect_ul():
    try: os.mkdir("unified_logs")
    except: pass
    d.infobox("Collecting Unified Logs from devie. This may take some time.")
    try:
        OsTraceService(lockdown).collect(out= "unified_logs/" + udid + ".logarchive")
        d.msgbox("Unified Logs written to " + udid + ".logarchive")
    except:
        d.msgbox("Error: \nCoud not collect logs - Maybe the device or its iOS version is too old.")
        pass
    try: os.rmdir("unified_logs")
    except: pass
    wrapper(select_menu)

def mount_developer():
    d_images = {4:[2,3], 5:[0,1], 6:[0,1], 7:[0,1], 8:[0,1,2,3,4], 9:[0,1,2,3],
                10:[0,1,2,3], 11:[0,1,2,3,4], 12:[0,1,2,3,4], 13:[0,1,2,3,4,5,7],
                14:[0,1,2,4,5,6,7,7.1,8], 15:[0,1,2,3,3.1,4,5,6,6.1,7],
                16:[0,1,2,3,3.1,4,4.1,5,6,7]}
    try:
        if DeveloperDiskImageMounter(lockdown).copy_devices() != []:
            return("developer")
            developer_options()
    except:
        pass

    try:
        if lockdown.developer_mode_status == True:
            pass
        else:
            code = d.yesno("The device has to be rebooted in order to activate the developer mode.\n\nDo you want to restart the device?", width=35)
            if code == d.OK:
                AmfiService(lockdown).enable_developer_mode(enable_post_restart=True)
                d.msgbox("Wait for the device to reboot.\nUnlock it and confirm the activation of the developer mode.\n\nAfter this, press \"OK\".", width=35)
            else:
                wrapper(select_menu)
    except:
        pass
    try: 
        info = ("Looking for version " + version)
        d.infobox(info)
        time.sleep(1)
        DeveloperDiskImageMounter(lockdown).mount(image=os.path.dirname(__file__) + "/ufade_developer/Developer/" + version + "/DeveloperDiskImage.dmg", signature=os.path.dirname(__file__) + "/ufade_developer/Developer/" + version + "/DeveloperDiskImage.dmg.signature")
        #developer_options()    
    except:
        info = info + "\nVersion " + version + " not found"
        d.infobox(info)
        time.sleep(1)
        v = version.split(".")
        v_check = np.array(d_images[int(v[0])])
        v_diff = np.absolute(v_check - int(v[1]))
        index = v_diff.argmin()
        ver = str(v[0]) + "." + str(d_images[int(v[0])][index])
    finally:
        if int(v[0]) <= 10 or DeveloperDiskImageMounter(lockdown).copy_devices() == []:
            info = info + "\nClosest version is " + ver
            d.infobox(info)
            time.sleep(1)
            try: 
                DeveloperDiskImageMounter(lockdown).mount(image=os.path.dirname(__file__) + "/ufade_developer/Developer/" + ver + "/DeveloperDiskImage.dmg", signature=os.path.dirname(__file__) + "/ufade_developer/Developer/" + ver + "/DeveloperDiskImage.dmg.signature")
                info = info + "\nVersion: " + ver + " was used"
                return("developer")
            except: 
                for i in range(index)[::-1]:
                    ver = str(v[0]) + "." + str(d_images[int(v[0])][i])
                    try:
                        DeveloperDiskImageMounter(lockdown).mount(image=os.path.dirname(__file__) + "/ufade_developer/Developer/" + ver + "/DeveloperDiskImage.dmg", signature=os.path.dirname(__file__) + "/ufade_developer/Developer/" + ver + "/DeveloperDiskImage.dmg.signature")
                        info = info + "\nVersion: " + ver + " was used"
                        d.infobox(info)
                        time.sleep(1)
                        break
                    except:
                        pass
                if int(v[0]) <= 10:
                    return("developer")
                if DeveloperDiskImageMounter(lockdown).copy_devices() == []:
                    d.msgbox("DeveloperDiskImage not loaded")
                    return("nope")
                else:
                    d.msgbox("DeveloperDiskImage loaded")
                    return("developer")
            
        else:
            d.msgbox("DeveloperDiskImage loaded")
            return("developer")

def developer_options():
    if int(version.split(".")[0]) < 17 and mount_developer() == "developer":
        try:
            dvt = DvtSecureSocketProxyService(lockdown)
            dvt.__enter__()
        except:
            DeveloperDiskImageMounter(lockdown).umount()
            d.msgbox("Error. Try again.")
            wrapper(select_menu)
        code, tag = d.menu("Choose:",
        choices=[("(1)", "Take screenshots from device screen (PNG)", "Screenshots will be saved under \"screenshots\" as PNG"),
                ("(2)", "Write filesystem content to textfile", "Starting from the /var Folder. This may take some time. (iOS < 16)"),
                ("(3)", "Unmount DeveloperDiskImage", "Leave the developer mode."),],
                item_help=True, title=(dev_name + ", iOS " + version))
        if code == d.OK:
            if tag == "(1)":
                try: os.mkdir("screenshots")
                except: pass
                screen_device(dvt)
            elif tag == "(2)":
                d.infobox("Creating filesystem list. This may take a while.")
                folders = []
                for line in DeviceInfo(dvt).ls("/"):
                    folders.append(line)
                fcount = len(folders)
                cnt = 0
                pathlist = []
                d.gauge_start("Processing filelist:")
                pathlist = fileloop(dvt, "/var", pathlist, fcount, cnt)
                d.gauge_update(100)
                d.gauge_stop()
                with open(udid + "_var_filesystem.txt", "w") as files:
                    for line in pathlist:
                        files.write("\n" + line)
                developer_options()
            elif tag == "(3)":
                try: 
                    DeveloperDiskImageMounter(lockdown).umount()
                except: 
                    d.msgbox("DeveloperDiskImage could not be unmounted. Restart the device to unmount.")
                    pass
                wrapper(select_menu)
            else:
                pass
        else:
            #DeveloperDiskImageMounter(lockdown).umount()
            wrapper(select_menu)
    else:
        wrapper(select_menu)

def fileloop(dvt, start, lista, fcount, cnt):
    pathlist = lista
    try: 
        next = DeviceInfo(dvt).ls(start)
        for line in next:
            next_path = (start + "/" + line)
            if len(next_path.split("/")) == 3:
                cnt += 1
                fpro = int(44*(cnt/fcount))%100
                d.gauge_update(fpro, "Processing filelist:\nFolder: " + next_path, update_text=True)
            #if cnt % 66 == 1:
            #    try: d.infobox("Processing: " + next_path)
            #    except: pass
            if next_path in pathlist:
                break
            else:
                pathlist.append(next_path)
                fileloop(dvt, next_path, pathlist, fcount, cnt)       
    except: 
        pass
    finally:
        return(pathlist)

def screen_device(dvt):
    ls = os.listdir(path="screenshots")
    lss = "\n".join(str(element) for element in ls)
    #shot = d.yesno("To create a screenshot of the current screen press: \n\"Screenshot\"", yes_label="Screenshot", no_label="Abort")
    shot = d.yesno("Screenshots taken:\n\n" + lss, height=18, width=52, yes_label="Screenshot", no_label="Abort")
    if shot == d.OK:
        try: 
            png = Screenshot(dvt).get_screenshot()
        except: 
            png = ScreenshotService(lockdown).take_screenshot()
        with open("screenshots/" + hardware + "_" + str(datetime.now().strftime("%m_%d_%Y_%H_%M_%S")) + ".png", "wb") as file:
            file.write(png)
        screen_device(dvt)
    else:
        developer_options()

#Start:

lockdown = check_device()

# Get device information #
dev_name = lockdown.display_name
hardware = lockdown.hardware_model               
product = lockdown.product_type            
language = lockdown.language
udid = lockdown.udid
ecid = str(lockdown.ecid)
name =  lockdown.get_value("","DeviceName")
mnr = lockdown.get_value("", "ModelNumber")
try: imei = lockdown.get_value("","InternationalMobileEquipmentIdentity")
except: imei = " "
try: imei2 = lockdown.get_value("","InternationalMobileEquipmentIdentity2") 
except: imei2 = " "
version = lockdown.product_version
build = lockdown.get_value("","BuildVersion")
snr = lockdown.get_value("","SerialNumber")
mlbsnr = lockdown.get_value("","MLBSerialNumber")
b_mac = lockdown.get_value("","BluetoothAddress")
w_mac = lockdown.wifi_mac_address# Licensed under GPLv3 License
disk1 = lockdown.get_value("com.apple.disk_usage","TotalDiskCapacity")/1000000000
disk = str(round(disk1,2))
free1 = lockdown.get_value("com.apple.disk_usage","AmountDataAvailable")/1000000000
free = str(round(free1,2))
used1 = disk1 - free1
used = str(round(used1,2))
graph_progress = "" + "▓" * int(30/100*(100/disk1*used1)) + "░" * int(30/100*(100/disk1*free1)) + ""
d_class = lockdown.get_value("","DeviceClass")

#Get installed Apps
apps = installation_proxy.InstallationProxyService(lockdown).get_apps("User")
app_id_list = []
for app in apps.keys():
    app_id_list.append(app)

#Document Sharing enabled?
doc_list = []
for app in apps:
    try: 
        apps.get(app)['UIFileSharingEnabled']
        doc_list.append("yes")
    except:
        doc_list.append("no")

show_device()
dir = chdir()
wrapper(select_menu)

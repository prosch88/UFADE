#!/usr/bin/env python3
# UFADE - Universal Forensic Apple Device Extractor (c) C.Peter 2024
# Licensed under GPLv3 License
from pymobiledevice3 import usbmux, exceptions, lockdown
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services import installation_proxy
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
from pymobiledevice3.services.springboard import SpringBoardServicesService
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.crash_reports import CrashReportsManager
from dialog import Dialog
from iOSbackup import iOSbackup
from datetime import datetime, timedelta, timezone
import pandas as pd
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
def select_menu():
    code, tag = d.menu("Choose:",
    choices=[("(1)", "Save device information to text", "Save device information and a list of user-installed apps to a textfile"),
             ("(2)", "Logical (iTunes-Style) Backup", "Perform a backup as iTunes would do it."),
             ("(3)", "Logical+ Backup", "Perform and decrypt an iTunes backup, gather AFC-media files, shared App folders and crash reports."),
             ("(4)", "Logical+ Backup (UFED-Style)", "Creates an advanced Logical Backup as ZIP with an UFD File for PA.")],
             item_help=True)
    if code == d.OK:
        if tag == "(1)":
            save_info_menu()
        elif tag == "(2)":
            perf_itunes()
        elif tag == "(3)":
            perf_logical_plus(None)
        elif tag == "(4)":
            perf_logical_plus("UFED")
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

def save_info_menu():
    save_info()
    d.msgbox("Info written to device_" + udid + ".txt")
    select_menu()

#Perform iTunes Backup

def iTunes_bu(mode):
    m = mode
    pw_found = 0

    #Check for active Encryption and activate
    try:
        beep_timer = threading.Timer(8.0,notify)
        beep_timer.start()
        d.infobox("Checking Backup Encryption.\n\nUnlock device with PIN/PW if prompted")            
        c1 = str(Mobilebackup2Service(lockdown).change_password(new="12345"))
        if c1 == "None":
            beep_timer.cancel()
        d.infobox("New Backup password: \"12345\" \n\nStarting Backup...\n\nUnlock device with PIN/PW")
        pw_found = 1            
        
    except:
        code = d.yesno("Backup Encryption is activated with password. Is the password known?")
        if code == d.OK:
            code, user_input = d.inputbox("Enter the password:", title="Backup password: ")
            if code == d.OK:
                pw = user_input
                try: 
                    Mobilebackup2Service(lockdown).change_password(old=pw)
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
                        select_menu()

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
                    code_reset = d.yesno("Dictionary exhausted. Do you want to reset the Password on the device?")
                    if code_reset == d.OK:
                        icons = SpringBoardServicesService(lockdown).get_icon_state()
                        d.msgbox("Unlock the device. \nOpen the \"Settings\"-app \n--> \"General\" \n--> \"Reset\" (bottom) \n--> \"Reset all Settings\"\n\n"
                            + "You will loose known networks, user settings and dictionary. App and User-Data will remain.\n\nWait for the device to reboot and press \"OK\"", height=18, width=52)
                        
                        try:
                            beep_timer = threading.Timer(8.0,notify)
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
            d.infobox("Encryption has to be reactivated\n\nNew Password is: \"12345\" \n\nUnlock device with PIN/PW if prompted")
            try:
                beep_timer = threading.Timer(8.0,notify)
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
            Mobilebackup2Service(lockdown).backup(full=True,  progress_callback=lambda x: (d.gauge_update(int(x),"Performing " + m + " Backup: ",update_text=True)))
            d.gauge_stop()
            save_info()
            beep_timer = threading.Timer(8.0,notify)
            beep_timer.start()
            d.infobox("iTunes Backup complete! Trying to deactivate Backup Encryption again. \n\nUnlock device with PIN/PW if prompted") 
            c3 = str(Mobilebackup2Service(lockdown).change_password(old="12345"))
            if c3 == 'None':
                beep_timer.cancel()
        else:
            select_menu()

def perf_itunes():
    iTunes_bu("iTunes-Style")                                                                                           #call iTunes Backup with "iTunes-Style" written in dialog
    try: os.rename(udid, udid + "_iTunes")  
    except: pass                                                                                 #rename backup folder to prevent conflicts with other options
    d.msgbox("Backup completed!")
    select_menu()
    
#Make advanced Backup - l_type(t) defines the type: 'None' for regular; 'UFED' for UFED-Style
def perf_logical_plus(t):
    l_type = t
    try: os.mkdir(".tar_tmp")                                                                                           #create temp folder for files to zip/tar
    except: pass

    try: os.mkdir(".tar_tmp/itunes_bu")                                                                                 #create folder for decrypted backup
    except: pass
    now = datetime.now()
    iTunes_bu("Logical+")                                                                                               #call iTunes Backup with "Logical+" written in dialog
    
    if l_type != "UFED":
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
        shutil.rmtree(".tar_tmp/itunes_bu")                                                                             #remove the backup folder
        shutil.rmtree(udid)
        
    else:
        zipname = "Apple_" + hardware.upper() + " " + dev_name + ".zip"                                                 #create ZIP-File for CLB PA (TAR-handling isn't as good here)
        zip = zipfile.ZipFile(zipname, "w")
        d.infobox("Processing Backup ...")
        base = udid
        for root, dirs, files in os.walk(base):
            for file in files:
                source_file = os.path.join(root, file)
                filename = os.path.relpath(source_file, base)
                zip.write(source_file, arcname=os.path.join("iPhoneDump/Backup Service", udid, "Snapshot", filename))   #just copy the encrypted backup to a ZIP
                
        shutil.rmtree(udid)                                                                                             #delete the backup after zipping

#Gather Media Directory
    media_list = []
    d.gauge_start("Performing AFC Extraction of Mediafiles")
    for line in AfcService(lockdown).listdir("/"):
            media_list.append(line)                                                                                     #get amount of lines (files and folders) in media root
    media_count = len(media_list)
    try: os.mkdir(".tar_tmp/media")
    except: pass
    m_nr = 0
    for entry in media_list:
        m_nr += 1
        mpro = int(100*(m_nr/media_count))
        d.gauge_update(mpro)
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
    d.gauge_stop()
    shutil.rmtree(".tar_tmp/media")                                                                                     #remove media-folder

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
            AfcService(lockdown, service_name="com.apple.crashreportcopymobile").pull(relative_src=entry, dst=".tar_tmp/Crash", src_dir="")
            cpro = int(100*(c_nr/crash_count))
            d.gauge_update(cpro)
        tar.add(".tar_tmp/Crash", arcname=("/Crash"), recursive=True)
        d.gauge_update(100)
        d.gauge_stop()
        shutil.rmtree(".tar_tmp/Crash")

        
#Gather device information for UFD-ZIP
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
            de_va_di.update([(key,(lockdown.get_value("",key)))])
        for key in de_va2:
            de_va_di.update([(key,(lockdown.get_value(key,"")))])

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
    select_menu()

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
select_menu()

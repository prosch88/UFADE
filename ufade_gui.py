#!/usr/bin/env python3
# UFADE - Universal Forensic Apple Device Extractor (c) C.Peter 2024
# Licensed under GPLv3 License
import customtkinter as ctk
from PIL import ImageTk, Image, ExifTags
from tkinter import StringVar
from pymobiledevice3 import usbmux, exceptions, lockdown
from pymobiledevice3.services.mobile_image_mounter import DeveloperDiskImageMounter, MobileImageMounterService, PersonalizedImageMounter
from pymobiledevice3.lockdown import create_using_usbmux, create_using_remote
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.companion import CompanionProxyService
from pymobiledevice3.services import installation_proxy
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
from pymobiledevice3.services.springboard import SpringBoardServicesService
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.crash_reports import CrashReportsManager
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
from pymobiledevice3.services.screenshot import ScreenshotService
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit, Direction
from pymobiledevice3.services.amfi import AmfiService
from pymobiledevice3.tcp_forwarder import UsbmuxTcpForwarder
from pymobiledevice3.services.pcapd import PcapdService
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.remote.module_imports import MAX_IDLE_TIMEOUT, start_tunnel, verify_tunnel_imports
from pymobiledevice3.tunneld import TUNNELD_DEFAULT_ADDRESS, TunnelProtocol, TunneldRunner, get_tunneld_devices, get_rsds
from pymobiledevice3.services.os_trace import OsTraceService
from paramiko import SSHClient, AutoAddPolicy, Transport
from datetime import datetime, timedelta, timezone, date
from subprocess import Popen, PIPE, check_call, run
from pymobiledevice3 import exceptions
from importlib.metadata import version
from iOSbackup import iOSbackup
from pyiosbackup import Backup
from playsound import playsound
from io import BytesIO
import xml.etree.ElementTree as ET
from xml.dom import minidom
import mimetypes
import hashlib
import json
import plistlib
import posixpath
import pathlib
import numpy as np
import pandas as pd
import shutil
import tarfile
import zipfile
import threading
import platform
import sys
import os
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")
import time
import tempfile
import re
import exifread
import uuid

ctk.set_appearance_mode("dark")  # Dark Mode
ctk.set_default_color_theme("dark-blue") 

class MyApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.stop_event = threading.Event()

        # Define Window
        self.title("Universal Forensic Apple Device Extractor 0.8.1")
        self.geometry("1100x600")
        self.resizable(False, False)
        self.iconpath = ImageTk.PhotoImage(file=os.path.join(os.path.dirname(__file__), "assets" , "ufade.png" ))
        self.wm_iconbitmap()
        self.iconphoto(False, self.iconpath)

        # Font:
        self.stfont = ctk.CTkFont("default")
        self.stfont.configure(size=14)

        # Create frames
        self.left_frame = ctk.CTkFrame(self, width=340, corner_radius=0, fg_color="#2c353e", bg_color="#2c353e")
        self.left_frame.grid(row=0, column=0, sticky="ns", )

        self.right_frame = ctk.CTkFrame(self)
        self.right_frame.grid(row=0, column=1, sticky="nsew")
        self.grid_columnconfigure(1, weight=1)

        # Widgets (left Frame))
        if platform.uname().system == 'Windows':
            self.info_text = ctk.CTkTextbox(self.left_frame, height=600, width=340, fg_color="#2c353e", corner_radius=0, font=("Consolas", 14), activate_scrollbars=False)
        elif platform.uname().system == 'Darwin':
            self.info_text = ctk.CTkTextbox(self.left_frame, height=600, width=340, fg_color="#2c353e", corner_radius=0, font=("Menlo", 14), activate_scrollbars=False)
        else:
            self.info_text = ctk.CTkTextbox(self.left_frame, height=600, width=340, fg_color="#2c353e", corner_radius=0, font=("monospace", 14), activate_scrollbars=False)
        if lockdown != None:
            self.info_text.configure(text_color="#abb3bd")
        else:
            self.info_text.configure(text_color="#4d5760")
        self.info_text.insert("0.0", device)
        self.info_text.configure(state="disabled")
        self.info_text.pack(padx=10, pady=10)

        # Initialize menu
        self.menu_var = StringVar(value="MainMenu")

        # Placeholder for dynamic frame
        self.dynamic_frame = ctk.CTkFrame(self.right_frame, corner_radius=0)
        self.dynamic_frame.pack(fill="both", expand=True, padx=0, pady=0)
        self.current_menu = None

        # Show Main Menu
        if lockdown != None:
            if ispaired != False:
                self.show_cwd()
            else:
                self.show_notpaired()
        else:
            self.show_nodevice()

    def show_main_menu(self):
         # Erase content of dynamic frame
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        global lockdown
        lockdown = create_using_usbmux()
        # Show Main Menu
        self.menu_var.set("MainMenu")
        self.current_menu = "MainMenu"
        self.skip = ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=20, font=self.stfont)
        self.skip.grid(row=0, column=1, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Save device info", command=lambda: self.switch_menu("DevInfo"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Acquisition Options", command=lambda: self.switch_menu("AcqMenu"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Collect Unified Logs", command=lambda: self.switch_menu("CollectUL"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Developer Options", command=lambda: self.switch_menu("CheckDev"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Advanced Options", command=lambda: self.switch_menu("AdvMenu"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Save informations about the device, installed apps,\nSIM and companion devices.", 
                          "Allows logical, advanced logical and filesystem\nextractions.", 
                          "Collects the AUL from the device and saves\nthem as a logarchive.",
                          "Access developer mode for further options.\nMainly screenshotting options.",
                          "More specific options for data handling."]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=400, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

    def switch_menu(self, menu_name):
        # Erase content of dynamic frame
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()

# Switch to chosen menu
        self.current_menu = menu_name
        if menu_name == "AcqMenu":
            self.show_acq_menu()
        elif menu_name == "DevMenu":
            self.show_dev_menu()
        elif menu_name == "CheckDev":    
            self.developer_options()
        elif menu_name == "AdvMenu":
            self.show_adv_menu()
        elif menu_name == "WatchMenu":
            self.show_watch_menu()
        elif menu_name == "ReportMenu":
            self.show_report_menu()
        elif menu_name == "DevInfo":
            self.show_save_device_info()
        elif menu_name == "iTunes":
            self.show_iTunes_bu()
        elif menu_name == "advanced":
            self.show_logicalplus()
        elif menu_name == "advanced_ufed":
            self.show_ufed()
        elif menu_name == "ffs_jail":
            self.perf_jailbreak_ssh_dump()
        elif menu_name == "tess":
            self.backup_tess()     
        elif menu_name == "sniff":
            self.show_sniffer()      
        elif menu_name == "CollectUL":
            self.show_collect_ul()
        elif menu_name == "CrashReport":
            self.show_crash_report()
        elif menu_name == "SysDiag":
            self.show_sysdiag()
        elif menu_name == "Media":
            self.show_media()
        elif menu_name == "FileLS":
            dvt = DvtSecureSocketProxyService(lockdown)
            dvt.__enter__()
            self.show_fileloop(dvt)
        elif menu_name == "Shot":
            dvt = DvtSecureSocketProxyService(lockdown)
            dvt.__enter__()
            self.screen_device(dvt)
        elif menu_name == "ChatLoop":
            dvt = DvtSecureSocketProxyService(lockdown)
            dvt.__enter__()
            self.chat_shotloop(dvt)
        elif menu_name == "Report":
            self.show_report()
        elif menu_name == "umount":
            self.call_unmount()
        elif menu_name == "NoDevice":
            self.show_nodevice()
        elif menu_name == "NotPaired":
            self.show_notpaired()

# Watch Menu
    def show_watch_menu(self):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        self.skip = ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=20, font=self.stfont)
        self.skip.grid(row=0, column=1, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Reporting Options", command=lambda: self.switch_menu("ReportMenu"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Collect Unified Logs", command=lambda: self.switch_menu("CollectUL"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Extract crash reports", command=lambda: self.switch_menu("CrashReport"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Initiate Sysdiagnose", command=lambda: self.switch_menu("SysDiag"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Extract AFC Media files", command=lambda: self.switch_menu("Media"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Extract device informations and content.", 
                          "Collects the AUL from the device and saves\nthem as a logarchive.", 
                          "Pull the crash report folder from the device.",
                          "Create a Sysdiagnose archive on the device and\npull it to the disk afterwards.", 
                          "Pull the \"Media\"-folder from the device\n(pictures, videos, recordings)"]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=400, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

# Watch Report Menu
    def show_report_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=20, font=self.stfont)
        self.skip.grid(row=0, column=1, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Save device info", command=lambda: self.switch_menu("DevInfo"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Create UFDR Report", command=lambda: self.switch_menu("Report"), width=200, height=70, font=self.stfont, state="disabled"),
        ]
        self.menu_text = ["Save informations about the device, installed apps,\nSIM and companion devices.",
                          "Create a UFDR-Zip container viewable\nin the Cellebrite Reader application"]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=400, height=70, font=self.stfont, anchor="w", justify="left"))
        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_watch_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

# Acquisition Menu
    def show_acq_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=20, font=self.stfont)
        self.skip.grid(row=0, column=1, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Logical Backup", command=lambda: self.switch_menu("iTunes"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Logical+ Backup", command=lambda: self.switch_menu("advanced"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Logical+ Backup\n(UFED-Style)", command=lambda: self.switch_menu("advanced_ufed"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Filesystem Backup\n(jailbroken)", command=lambda: self.switch_menu("ffs_jail"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Perform a backup as iTunes would do it.", 
                          "Perform and decrypt an iTunes backup, gather\nAFC-media files, shared App folders and crash reports.", 
                          "Creates an advanced Logical Backup as ZIP with an\nUFD File for PA.",
                          "Creates a FFS Backup of an already jailbroken Device"]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=400, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

# Developer Options Menu
    def show_dev_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=20, font=self.stfont)
        self.skip.grid(row=0, column=1, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Take screenshots", command=lambda: self.switch_menu("Shot"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Chat capture", command=lambda: self.switch_menu("ChatLoop"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Capture filesystem\nto text", command=lambda: self.switch_menu("FileLS"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Unmount\nDeveloperDiskImage", command=lambda: self.switch_menu("umount"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Take screenshots from device screen.\nScreenshots will be saved under \"screenshots\" as PNG.", 
                          "Loop through a chat taking screenshots.\nOne screenshot is taken per message.", 
                          "Write a filesystem list to a textfile. (iOS < 16)\nStarting from /var Folder. This may take some time.",
                          "Try to unmount the image. Reboot the device if this fails"]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=400, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

# Advanced Options Menu
    def show_adv_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=20, font=self.stfont)
        self.skip.grid(row=0, column=1, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Extract crash reports", command=lambda: self.switch_menu("CrashReport"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Initiate Sysdiagnose", command=lambda: self.switch_menu("SysDiag"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="WhatsApp export\n(PuMA)", command=lambda: self.switch_menu("tess"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Sniff device traffic", command=lambda: self.switch_menu("sniff"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Extract AFC Media files", command=lambda: self.switch_menu("Media"), width=200, height=70, font=self.stfont)
        ]
        self.menu_text = ["Pull the crash report folder from the device.",
                          "Create a Sysdiagnose archive on the device and\npull it to the disk afterwards.", 
                          "Perform an iTunes-style backup and extract Whatsapp\nfiles for PuMA (LE-tool).", 
                          "Captures the device network traffic as a pcap file.",
                          "Pull the \"Media\"-folder from the device\n(pictures, videos, recordings)"
                          ]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=400, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

# No device is seen in the usbmux list:
    def show_nodevice(self):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        self.after(10)
        global lockdown
        global ispaired
        lockdown = check_device()
        try:
            language = lockdown.language
            ispaired = True
        except:
            ispaired = False
        if lockdown == None:
            ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
            self.text = ctk.CTkLabel(self.dynamic_frame, width=400, height=250, font=self.stfont, anchor="w", justify="left")
            self.text.configure(text="No device found!\n\n" +
                            "Make sure the device is connected and confirm \nthe \"trust\" message on the device screen.\n\n" +
                            "On a Windows-system, make sure \"Apple Devices\" \nor \"iTunes\" is installed.")
            self.text.pack(pady=50)
            ctk.CTkButton(self.dynamic_frame, text="Check again", command=self.show_nodevice).pack(pady=10)
            self.info_text.configure(text_color="#4d5760")
        else:
            device = dev_data()
            self.info_text.configure(state="normal")
            self.info_text.delete("0.0", "end")
            self.info_text.configure(text_color="#abb3bd")
            self.info_text.insert("0.0", device)
            self.info_text.configure(state="disabled")
            if ispaired == True:
                self.after(100, self.show_cwd)
            else:
                self.after(100, self.show_notpaired)

# A device is connected but not trusted
    def show_notpaired(self):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        self.after(10)
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        self.text = ctk.CTkLabel(self.dynamic_frame, width=400, height=250, font=self.stfont, anchor="w", justify="left")
        self.text.configure(text="Device not paired!\n\n" +
                          "Make sure the device is connected and confirm \nthe \"trust\" message on the device screen.\n\n" +
                          "On a Windows-system, make sure \"Apple Devices\" \nor \"iTunes\" is installed.")
        self.text.pack(pady=50)
        global lockdown
        global ispaired
        try:
            language = lockdown.language
            ispaired = True
        except:
            ispaired = False
        if ispaired == False:
            ctk.CTkButton(self.dynamic_frame, text="Pair", command=self.pair_button).pack(pady=10)
        else:
            lockdown = check_device()
            device = dev_data()
            self.info_text.configure(state="normal")
            self.info_text.delete("0.0", "end")
            self.info_text.configure(text_color="#abb3bd")
            self.info_text.insert("0.0", device)
            self.info_text.configure(state="disabled")
            self.show_cwd()

# Select the working directory
    def show_cwd(self):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        global dir
        dir = os.getcwd()
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Choose Output Directory:", height=30, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.browsebutton = ctk.CTkButton(self.dynamic_frame, text="Browse", font=self.stfont, command=lambda: self.browse_cwd(self.outputbox), width=60, fg_color="#2d2d35")
        self.browsebutton.pack(side="bottom", pady=(0,410), padx=(0,415))
        self.outputbox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text=[dir])
        self.outputbox.bind(sequence="<Return>", command=lambda x: self.choose_cwd(self.outputbox))
        self.outputbox.insert(0, string=dir)
        self.outputbox.pack(side="left", pady=(110,0), padx=(130,0))  
        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.choose_cwd(self.outputbox))
        self.okbutton.pack(side="left", pady=(110,0), padx=(10,120))
        
# Function to choose the working directoy
    def choose_cwd(self, outputbox):
        global dir
        user_input = outputbox.get()
        try:
            if user_input == '':
                user_input = '.'
            os.chdir(user_input)
            dir = os.getcwd()
            pass
        except:
            os.mkdir(user_input)
            os.chdir(user_input)
            dir = os.getcwd()
        if d_class == "Watch":
            self.show_watch_menu()
        else:
            self.show_main_menu()

# Filebrowser for working direcory
    def browse_cwd(self, outputbox):
        global dir
        olddir = dir
        self.okbutton.configure(state="disabled")
        outputbox.configure(state="disabled")
        if platform.uname().system == 'Linux':
            import crossfiledialog
            dir = crossfiledialog.choose_folder()
            if dir == "":
                dir = olddir
        else:
            dir = ctk.filedialog.askdirectory()
            if not dir:
                dir = olddir
        self.okbutton.configure(state="enabled")
        outputbox.configure(state="normal")    
        outputbox.delete(0, "end")
        outputbox.insert(0, string=dir)
        
# Save device info to file and show the available content
    def show_save_device_info(self):
        save_info()
        text = "Device info saved to: \ndevice_" + udid + ".txt\n\nContains:\n- device information\n"
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        if number != "":
            text = text + "- phone number\n"
        if comp != []:
            text = text + "- companion udid\n"
        if all != "" and None:
            text = text + "- SIM information\n"
        if app_id_list != []:
            text = text + "- app information"
        self.text = ctk.CTkLabel(self.dynamic_frame, width=420, height=200, font=self.stfont, text=text, anchor="w", justify="left")
        self.text.pack(pady=50)
        if d_class == "Watch":
            ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_watch_menu).pack(pady=10)
        else:
            ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=10)        
        

# Unified Logs Collecting screen
    def show_collect_ul(self):
        save_info()
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Collect Unified Logs", height=80, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Collecting Unified Logs will take some time.\ndo you want to continue?", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=25)
        self.choose = ctk.BooleanVar(self, False)
        self.yesb = ctk.CTkButton(self.dynamic_frame, text="YES", font=self.stfont, command=lambda: self.choose.set(True))
        self.yesb.pack(side="left", pady=(0,350), padx=140)
        self.nob = ctk.CTkButton(self.dynamic_frame, text="NO", font=self.stfont, command=lambda: self.choose.set(False))
        self.nob.pack(side="left", pady=(0,350))    
        self.wait_variable(self.choose)                             
        if self.choose.get() == True:  
            self.yesb.pack_forget()
            self.nob.pack_forget()    
            self.text.configure(text="Collecting Unified Logs from device.\nThis may take some time.")
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
            self.progress.pack()
            self.progress.start()
            self.waitul = ctk.IntVar(self, 0)
            self.coll = threading.Thread(target=lambda: self.collect_ul(time=None, text=self.text, waitul=self.waitul))
            self.coll.start()
            self.wait_variable(self.waitul)
            self.progress.stop()
            self.progress.pack_forget()
            if d_class == "Watch":
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_watch_menu).pack(pady=10)
            else:
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=10)
        else:
            if d_class == "Watch":
                self.show_watch_menu()
            else:
                self.show_main_menu()

# Crash Report extraction as single function or as part of a flow
    def show_crash_report(self, dir="Crash Report", flow=False):
        save_info()
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Extract Crash Reports", height=80, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Extracting crash reports from device.\nThis may take some time.", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=25)
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.progress.pack()
        self.change = ctk.IntVar(self, 0)
        self.crash = threading.Thread(target=lambda: crash_report(crash_dir=dir, change=self.change, progress=self.progress, prog_text=self.prog_text))
        self.crash.start()
        self.wait_variable(self.change)
        self.progress.stop()
        self.progress.pack_forget()
        self.prog_text.pack_forget()
        if flow == False:
            self.text.configure(text="Extraction of crash reports completed!")
            if d_class == "Watch":
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_watch_menu).pack(pady=10)
            else:
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AdvMenu")).pack(pady=10)
        else:
            pass

    def show_sysdiag(self):
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Extract Sysdiagnose", height=40, width=585, font=("standard",24), justify="left").pack(pady=15)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Initiate the creation of a Sysdiagnose archive on the device and save \nit to disk afterwards. This may take some time. \nDo you want to continue?", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=60)

        self.diagsrv = CrashReportsManager(lockdown)
        self.choose = ctk.BooleanVar(self, False)
        self.yesb = ctk.CTkButton(self.dynamic_frame, text="YES", font=self.stfont, command=lambda: self.choose.set(True))
        self.yesb.pack(side="left", pady=(0,350), padx=140)
        self.nob = ctk.CTkButton(self.dynamic_frame, text="NO", font=self.stfont, command=lambda: self.choose.set(False))
        self.nob.pack(side="left", pady=(0,350))    
        self.wait_variable(self.choose)                             
        if self.choose.get() == True: 
            self.yesb.pack_forget()
            self.nob.pack_forget() 
            self.text.pack_forget()
            if d_class == "Watch":
                self.text.configure(text="To trigger the creation of the Sysdiagnose files,\npress: Power/Side + Digital Crown for 0.215 seconds.")
            else:
                self.text.configure(text="To trigger the creation of the Sysdiagnose files,\npress: Power/Side + VolUp + VolDown for 0.215 seconds.")
            self.text.pack(pady=10)
            if d_class == "Watch":
                self.diag_image = ctk.CTkImage(dark_image=Image.open(os.path.join(os.path.dirname(__file__), "assets" , "diag_watch.png")), size=(600, 300))
            elif d_class == "iPad":
                self.diag_image = ctk.CTkImage(dark_image=Image.open(os.path.join(os.path.dirname(__file__), "assets" , "diag_ipad.png")), size=(600, 300))
            else:
                self.diag_image = ctk.CTkImage(dark_image=Image.open(os.path.join(os.path.dirname(__file__), "assets" , "diag.png")), size=(600, 300))
            self.diaglabel = ctk.CTkLabel(self.dynamic_frame, image=self.diag_image, text=" ", width=600, height=300, font=self.stfont, anchor="w", justify="left")
            self.diaglabel.pack()
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
            self.waitsys = ctk.IntVar(self, 0)
            self.diag = threading.Thread(target=lambda: self.sysdiag(self.text, self.progress, self.waitsys))
            self.diag.start()
            self.wait_variable(self.waitsys)
            if d_class == "Watch":
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_watch_menu).pack(pady=10)
            else:
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AdvMenu")).pack(pady=10)     
        else:
            if d_class == "Watch":
                self.show_watch_menu()
            else:
                self.switch_menu("AdvMenu")

    def sysdiag(self, text, progress, waitsys):
        self.abort = ctk.CTkButton(self.dynamic_frame, text="Abort", font=self.stfont, command=self.abort_diag)
        self.abort.pack(pady=15)
        sysdiagname = None
        try:
            sysdiagname = self.diagsrv._get_new_sysdiagnose_filename()
            self.abort.pack_forget()
            self.diaglabel.pack_forget()
            text.pack_forget()
            text.configure(text="Creation of Sysdiagnose archive has been started.")
            text.pack(pady=60)
            progress.pack()
            progress.start()
            self.diagsrv._wait_for_sysdiagnose_to_finish()
            text.configure(text="Pulling the Sysdiagnose archive from the device")
            self.diagsrv.pull(out=f"{udid}_sysdiagnose.tar.gz", entry=sysdiagname,erase=True)
            text.configure(text="Extraction of Sysdiagnose archive completed!")
            progress.pack_forget()
        except:
            text.configure(text="Extraction of Sysdiagnose canceled!")
            self.diaglabel.pack_forget()
            self.abort.pack_forget()
            progress.pack_forget()

        finally:
            waitsys.set(1)
            return

    def abort_diag(self):
        self.diagsrv.close()

# manually send a pair command and call "notpaired" again to check the status
    def pair_button(self):
        self.paired = ctk.BooleanVar(self, False)
        self.pair = threading.Thread(target=lambda: pair_device(paired=self.paired))
        self.pair.start()
        self.wait_variable(self.paired)
        self.show_notpaired()

# Play a notification sound
    def notification(self):      
        playsound(os.path.join(os.path.dirname(__file__), "assets", "notification.mp3"))

# Unified logs collection function
    def collect_ul(self, time, text, waitul):
        try: os.mkdir("unified_logs")
        except: pass

        try:
            OsTraceService(lockdown).collect(out= os.path.join("unified_logs", udid + ".logarchive"), start_time=time)
            text.configure(text="Unified Logs written to " + udid + ".logarchive")
            waitul.set(1)  
        except:
            text.configure(text="Error: \nCoud not collect logs - Maybe the device or its iOS version is too old.")
            waitul.set(1)
        try: os.rmdir("unified_logs")
        except: pass

# Call the iTunes Backup
    def show_iTunes_bu(self):
        self.perf_iTunes_bu("iTunes")

# Call the advanced Backup in UFADE-Mode
    def show_logicalplus(self):
        self.perf_logical_plus("UFADE")

# Call the advanced Backup in UFED-Mode
    def show_ufed(self):
        self.perf_logical_plus("UFED")

# Check, if the device has a backup password and set one
    def check_encryption(self, change):
        try:
            Mobilebackup2Service(lockdown).change_password(new="12345")
            change.set(1)
        except:
            change.set(2)

# Try to deactivate encryption after the Backup is complete
    def deactivate_encryption(self, change, text=None):
        try:
            Mobilebackup2Service(lockdown).change_password(old="12345")
            change.set(1)
        except:
            change.set(2)
        if text != None:
            text.configure(text="Backup password got removed.\nBackup complete.")  
        else:
            pass

# Progress output for iTunes Backup
    def show_process(self,x, progress, text, change, beep_timer, setext):
        beep_timer.cancel()
        setext.configure(text="Backup in progress.\nDo not disconnect the device.") 
        proc = x / 100
        progress.set(proc)
        text.configure(text=f"{int(x)}%")
        progress.update()
        text.update()
        #if x == 100:
        #    change.set(1)

# Check for Backup function to complete
    def schedule_check(self, t, change):
        self.after(1000, lambda: self.check_if_done(t,change))

    def check_if_done(self, t, change):
        # If the thread has finished, re-enable the button and show a message.
        if not t.is_alive():
            self.change.set(1)
        else:
            self.schedule_check(t, change)

# Start a thread for the 
    def call_known_pw(self, passwordbox, pw_found, okbutton, abort, text):
        known = threading.Thread(target=lambda: self.password_known(passwordbox, pw_found, okbutton, abort, text))
        known.start() 

# Function to check the possibly known backup-password
    def password_known(self, passwordbox, pw_found, okbutton, abort, text):
        pw=passwordbox.get()
        try:
            Mobilebackup2Service(lockdown).change_password(old=pw)                     #Try to deactivate backup encryption with the given password
            passwordbox.pack_forget()
            okbutton.pack_forget()
            abort.pack_forget()
            text.configure(text="New Backup password: \"12345\" \nStarting Backup.\nUnlock device with PIN/PW")
            pw_found.set(1)
        except:
            text.configure(text="Wrong password.\nProvide the correct backup password:\n(UFADE sets this to \"12345\")")

# Filedialog for selecting the password-list for the backup password
    def pw_file_call(self):
        global pw_file
        if platform.uname().system == 'Linux':
            pw_file = crossfiledialog.open_file()
        else:
            pw_file = ctk.filedialog.askopenfilename()

# Actually bruteforcing the backup password
    def brute_bu_pw(self, pw_list, progress, prog_text, text, pw_count, pw_found):
        pw_num = 0
        pw_pro = 0
        for pw in pw_list:
            progress.set(pw_pro)
            prog_text.configure(text=f"{int(pw_pro*100)}%")
            progress.update()
            prog_text.update()                   
            try: 
                Mobilebackup2Service(lockdown).change_password(old=pw)
                text.configure(text="Password found: " + pw)
                pw_found.set(1)
                break
            except:
                pass
            pw_num += 1
            pw_pro = pw_num/pw_count
        if pw_found.get() != 1:
            pw_found.set(0)
        else:
            pass          

# Main iTunes Backup function for other methods
    def perf_iTunes_bu(self, mode):
        m = mode
        global notify
        self.pw_found = ctk.IntVar(self,0)
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text=f"{m} Backup", height=80, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Checking Backup Encryption.\nUnlock device with PIN/PW if prompted", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)        
        
        #Check for active Encryption and activate
        beep_timer = threading.Timer(13.0,self.notification)                                                                           
        self.change = ctk.IntVar(self, 0)
        beep_timer.start()
        checkenc = threading.Thread(target=lambda: self.check_encryption(change=self.change))
        checkenc.start()
        self.wait_variable(self.change)
        beep_timer.cancel()

        if self.change.get() == 1:
            self.change.set(0)                 
            #Try to activate backup encryption with password "12345"
            self.text.configure(text="New Backup password: \"12345\" \nStarting Backup.\nUnlock device with PIN/PW")
            self.pw_found.set(1)
            self.change.set(1)            
            
        else:
            self.choose = ctk.BooleanVar(self, False)
            self.text.configure(text="Backup Encryption is activated with password.\n\nIs the password known?")
            self.yesb = ctk.CTkButton(self.dynamic_frame, text="YES", font=self.stfont, command=lambda: self.choose.set(True))
            self.yesb.pack(side="left", pady=(0,350), padx=140)
            self.nob = ctk.CTkButton(self.dynamic_frame, text="NO", font=self.stfont, command=lambda: self.choose.set(False))
            self.nob.pack(side="left", pady=(0,350))    
            self.wait_variable(self.choose)                             
            if self.choose.get() == True:
                self.yesb.pack_forget()
                self.nob.pack_forget()
                self.choose.set(False)
                self.passwordbox = ctk.CTkEntry(self.dynamic_frame, width=200, height=20, corner_radius=0)
                self.passwordbox.bind(sequence="<Return>", command=lambda x: self.call_known_pw(self.passwordbox, self.pw_found, self.okbutton, self.abort, self.text))
                self.passwordbox.pack(side="left", pady=(0,350), padx=(130,0))                
                self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.call_known_pw(self.passwordbox, self.pw_found, self.okbutton, self.abort, self.text))
                self.okbutton.pack(side="left", pady=(0,350), padx=(10,120))
                self.abort = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, command=lambda: self.switch_menu("AcqMenu"))
                self.abort.pack(side="bottom", ipadx=(140), pady=(0, 260), padx=(0,40))
                self.wait_variable(self.pw_found)
            else:
                self.text.configure(text="Do you want to attemt a password bruteforce?\n(Disable PIN/PW on Device beforehand)") 
                self.wait_variable(self.choose)                    
                if self.choose.get() == True:
                    pw_list_true = False
                    self.text.configure(text="Do you want to use the provided dictionary?")
                    self.wait_variable(self.choose)
                    self.yesb.pack_forget()
                    self.nob.pack_forget()    
                    if self.choose.get() == True:
                        try:
                            with open(os.path.join(os.path.dirname(__file__), "bu_pw.txt")) as pwds:
                                    pw_list = pwds.read().splitlines()
                                    pw_count = len(pw_list)
                                    pw_list_true = True
                        except:
                            self.text.configure(text="Error loading file!")
                            self.after(200, ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=10))
                            
                    else:
                        self.pw_file_call()
                        try:
                            with open(pw_file) as pwds:
                                pw_list = pwds.read().splitlines()
                                pw_count = len(pw_list)
                                pw_list_true = True
                        except:
                            self.text.configure(text="Error loading file!")
                            self.after(200, ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=10))
                    if pw_list_true == True:
                        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
                        self.prog_text.pack()
                        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
                        self.progress.set(0)
                        self.progress.pack()
                        self.text.configure(text="Bruteforcing backup password on device: ")
                        self.text.update()
                        brute_bu_pw = threading.Thread(target=lambda: self.brute_bu_pw(pw_list=pw_list, progress=self.progress, prog_text=self.prog_text, text=self.text, pw_count=pw_count, pw_found=self.pw_found))
                        brute_bu_pw.start()

                        self.wait_variable(self.pw_found)    
                        self.progress.stop()
                        self.progress.pack_forget() 
                        self.prog_text.pack_forget()
                else:
                    self.switch_menu("AcqMenu")
   
        if self.pw_found.get() == 1:
            self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
            self.prog_text.pack() 
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
            self.progress.set(0)
            self.progress.pack()
            self.change.set(0)
            beep_timer = threading.Timer(13.0,self.notification) 
            beep_timer.start()
            startbu = threading.Thread(target=lambda:Mobilebackup2Service(lockdown).backup(full=True, progress_callback=lambda x: self.show_process(x, self.progress, self.prog_text, self.change, beep_timer, self.text)))
            startbu.start()
            self.check_if_done(startbu, self.change)
            self.wait_variable(self.change)
            self.after(500, save_info())
            self.prog_text.pack_forget()
            self.progress.pack_forget()
            if m == "iTunes" or m == "PuMA":
                self.text.configure(text="iTunes Backup complete!\nTrying to deactivate Backup Encryption again. \nUnlock device with PIN/PW if prompted")
                self.change.set(0)
                beep_timer = threading.Timer(13.0,self.notification)  
                beep_timer.start()
                remove_enc = threading.Thread(target=lambda: self.deactivate_encryption(change=self.change, text=self.text))
                remove_enc.start()
                self.wait_variable(self.change)
                beep_timer.cancel()
                if m == "iTunes":
                    self.after(500, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))
            else:
                pass
        else:
            pass

# Advanced Logical Backup Fuctions

# Prepare for Backup decryption
    def init_backup_decrypt(self, change):
        global b
        global backupfiles
        try:
            b = iOSbackup(udid=udid, cleartextpassword="12345", derivedkey=None, backuproot="./")                           #Load Backup with Password
            key = b.getDecryptionKey()                                                                                      #Get decryption Key
            b = iOSbackup(udid=udid, derivedkey=key, backuproot="./")                                                       #Load Backup again with Key
            backupfiles = pd.DataFrame(b.getBackupFilesList(), columns=['backupFile','domain','name','relativePath'])
            change.set(1)
        except:
            change.set(2)

# Decrypting / "unbacking" the Backup
    def decrypt_itunes(self, b, backupfiles, tar, progress, prog_text, line_list, line_cnt, d_nr, change):
        for file in line_list:
            fileout = file
            if platform.uname().system == 'Windows':
                fileout = re.sub(r"[?%*:|\"<>\x7F\x00-\x1F]", "-", file)
            d_nr += 1
            dpro = int(100*(d_nr/line_cnt))
            progress.set(dpro/100)
            prog_text.configure(text=f"{int(dpro)}%")
            progress.update()
            prog_text.update()
            b.getFileDecryptedCopy(relativePath=file, targetName=fileout, targetFolder=os.path.join(".tar_tmp", "itunes_bu"))               #actually decrypt the backup-files
            file_path = os.path.join('.tar_tmp', 'itunes_bu', fileout)
            tar.add(file_path, arcname=os.path.join("iTunes_Backup/", 
                backupfiles.loc[backupfiles['relativePath'] == file, 'domain'].iloc[0], file), recursive=False)         #add files to the TAR
            try: os.remove(file_path)                                                                                   #remove the file after adding
            except: pass
        change.set(1) 

# Fallback decrption function for older devices
    def decrypt_old_itunes(self, tar, change):
        bu = Backup.from_path(backup_path=udid, password="12345")
        unback_alt(bu, os.path.join(".tar_tmp", "itunes_bu"))
        tar.add(".tar_tmp/itunes_bu", arcname="iTunes_Backup/", recursive=True)
        change.set(1)

# Only decrypt Whatsaap (TESS)
    def decrypt_whatsapp(self, change, wachange):
        finish = False
        if wachange.get() in [1,3]:
            app = "Whatsapp"
            domain = "AppDomainGroup-group.net.whatsapp.WhatsApp.shared"
            folder = "WA_PuMA"
        elif wachange.get() == 2:
            app = "Whatapp Business"
            domain = "AppDomainGroup-group.net.whatsapp.WhatsAppSMB.shared"
            folder = "WAB_PuMA"
        try:
            b.getFolderDecryptedCopy(targetFolder=folder, includeDomains=domain)
            shutil.move(os.path.join(folder,domain,"Message", "Media"), os.path.join(folder,"Media"))
            shutil.move(os.path.join(folder,domain,"Media", "Profile"), os.path.join(folder,"Profile"))
            shutil.move(os.path.join(folder,domain,"ChatStorage.sqlite"), os.path.join(folder,"ChatStorage.sqlite"))
            shutil.rmtree(os.path.join(folder,domain))
            finish = True
        except:
            self.text.configure(text=f"An error occured while extracting {app}. Try again.")
            pass
        if wachange.get() == 3:
            wachange.set(2)
            self.decrypt_whatsapp(change, wachange)
        else:
            pass
        if finish == True:
            self.after(100, lambda: self.text.configure(text="Whatsapp files extracted.")) 
        change.set(1)

    def decrypt_whatsapp_alt(self,change, wachange):
        finish = False
        if wachange.get() in [1,3]:
            app = "Whatsapp"
            domain = "AppDomainGroup-group.net.whatsapp.WhatsApp.shared"
            folder = "WA_PuMA"
        if wachange.get() == 2:
            app = "Whatapp Business"
            domain = "AppDomainGroup-group.net.whatsapp.WhatsAppSMB.shared"
            folder = "WAB_PuMA"
        try: os.mkdir(folder)
        except: pass
        try:
            bu = Backup.from_path(backup_path=udid, password="12345")
            dest_dir = pathlib.Path(folder)
            for file in bu.iter_files():
                if file.domain == domain:
                    dest_file = dest_dir / file.domain / file.relative_path
                    dest_file.parent.mkdir(exist_ok=True, parents=True)
                    dest_file.write_bytes(file.read_bytes())
            shutil.move(os.path.join(folder,domain,"Message", "Media"), os.path.join(folder,"Media"))
            shutil.move(os.path.join(folder,domain,"Media", "Profile"), os.path.join(folder,"Profile"))
            shutil.move(os.path.join(folder,domain,"ChatStorage.sqlite"), os.path.join(folder,"ChatStorage.sqlite"))
            shutil.rmtree(os.path.join(folder,domain))
            finish = True       
        except:
            self.text.configure(text=f"An error occured while extracting {app}. Try again.")
            pass
        finally:
            if wachange.get() == 3:
                wachange.set(2)
                #self.wabwait = ctk.IntVar(self, 0)
                self.decrypt_whatsapp_alt(change, wachange)
                #self.waitvar(self.wabwait)
            if finish == True:
                self.after(100, lambda: self.text.configure(text="Whatsapp files extracted.")) 
            change.set(1)

 # Move the backup files to a zip archive   
    def zip_itunes(self, zip, change):
        base = udid
        for root, dirs, files in os.walk(base):
            for file in files:
                source_file = os.path.join(root, file)
                filename = os.path.relpath(source_file, base)
                zip.write(source_file, arcname=os.path.join("iPhoneDump/Backup Service", udid, "Snapshot", filename)) 
        change.set(1)

# Extract shared app-documents
    def shared_app_files(self, prog_text, progress, change, media_count, tar=None, zip=None, l_type=None):
        m_nr = 0
        i = 0
        for app in app_id_list:
            if doc_list[i] == 'yes':
                m_nr += 1
                mpro = int(100*(m_nr/media_count))
                prog_text.configure(text=f"{mpro}%")
                progress.set(mpro/100)
                prog_text.update()
                progress.update()
                file_path = os.path.join(".tar_tmp/app_doc/", app, str((apps.get(app)['EnvironmentVariables'])['CFFIXED_USER_HOME'])[1:], "Documents/")
                os.makedirs(file_path, exist_ok=True)
                pull(self=HouseArrestService(lockdown, bundle_id=app, documents_only=True), relative_src="/Documents/.", dst=file_path)
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
        change.set(1)

# calculate the sha256 hash of the zip for the ufd
    def hash_ufd(self, change, zipname):
        global z_hash
        try:
            with open(zipname, 'rb', buffering=0) as z:
                z_hash = hashlib.file_digest(z, 'sha256').hexdigest()
        except:
            z_hash = " Error - Python >= 3.11 required"
        change.set(1)

# Actually perform the advanced logical backup
    def perf_logical_plus(self, t):
        l_type = t
        try: os.mkdir(".tar_tmp")                                                                                               #create temp folder for files to zip/tar
        except: pass

        try: os.mkdir(".tar_tmp/itunes_bu")                                                                                     #create folder for decrypted backup
        except: pass
        now = datetime.now()
        self.perf_iTunes_bu("Logical+")                                                                                                  #call iTunes Backup with "Logical+" written in dialog
        
        if l_type != "UFED":
            self.after(100, lambda: self.text.configure(text="Decrypting iTunes Backup: "))
            self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
            self.prog_text.pack() 
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
            self.progress.set(0)
            self.progress.pack()
            self.change.set(0)
            panda_backup = threading.Thread(target=lambda: self.init_backup_decrypt(self.change))
            panda_backup.start()
            self.wait_variable(self.change)
            if self.change.get() == 1:
                line_list = []
                line_cnt = 0
                for line in backupfiles['relativePath']:                                                                        #get amount of lines (files) of backup
                    if(line not in line_list):
                        line_cnt += 1
                        line_list.append(line)
                d_nr = 0
                self.change.set(0)                                                                     
                tar = tarfile.open(udid + "_logical_plus.tar", "w:")
                zip = None
                decrypt = threading.Thread(target=lambda: self.decrypt_itunes(b, backupfiles, tar, self.progress, self.prog_text, line_list, line_cnt, d_nr, self.change))
                decrypt.start()

            else:
                self.text.configure(text="Decrypting iTunes Backup - this may take a while.")
                self.prog_text.configure(text=" ")
                self.progress.pack_forget()
                self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
                self.progress.pack()
                self.progress.start()
                self.change.set(0)
                tar = tarfile.open(udid + "_logical_plus.tar", "w:") 
                zip = None
                self.decrypt = threading.Thread(target=lambda: self.decrypt_old_itunes(tar, self.change))
                self.decrypt.start()
            
            self.wait_variable(self.change)
            shutil.rmtree(".tar_tmp/itunes_bu")                                                                                 #remove the backup folder
            shutil.rmtree(udid)
            
            
        else:
            zipname = "Apple_" + hardware.upper() + " " + dev_name + ".zip"                                                     #create ZIP-File for CLB PA (TAR-handling isn't as good here)
            zip = zipfile.ZipFile(zipname, "w")
            tar = None
            self.after(100, lambda: self.text.configure(text="Processing Backup - this may take a while."))
            self.prog_text = ctk.CTkLabel(self.dynamic_frame, text=" ", width=585, height=20, font=self.stfont, anchor="w", justify="left")
            self.prog_text.pack()
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
            self.progress.pack()
            self.progress.start()
            self.zip_start = threading.Thread(target=lambda: self.zip_itunes(zip, self.change))
            self.zip_start.start()
            self.wait_variable(self.change)        
            shutil.rmtree(udid)                                                                                                 #delete the backup after zipping

        #Gather Media Directory
        try: os.mkdir(".tar_tmp/media")
        except: pass
        self.change.set(0)
        self.prog_text.configure(text="0%")
        self.progress.pack_forget()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.progress.pack()

        if l_type != "UFED":
            self.tar_media = threading.Thread(target=lambda: media_export(l_type=l_type, dest=".tar_tmp/media", archive=tar, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change))
            self.tar_media.start()
        else:
            self.zip_media = threading.Thread(target=lambda: media_export(l_type=l_type, dest=".tar_tmp/media", archive=zip, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change))
            self.zip_media.start()
        self.wait_variable(self.change)
        shutil.rmtree(".tar_tmp/media")                                                                                       #remove media-folder

        #Gather Shared App-Folders
        media_count = 0
        self.text.configure(text="Performing Extraction of Shared App-Files")
        for app in doc_list:
            if app == 'yes':
                media_count += 1

        try: os.mkdir(".tar_tmp/app_doc")
        except: pass
        self.change.set(0)
        self.prog_text.configure(text="0%")
        self.progress.pack_forget()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.progress.pack()
        self.app_pull = threading.Thread(target=lambda: self.shared_app_files(prog_text=self.prog_text, progress=self.progress, change=self.change, media_count=media_count, tar=tar, zip=zip, l_type=l_type))
        self.app_pull.start()
        self.wait_variable(self.change)
        shutil.rmtree(".tar_tmp/app_doc")

        #Gather Crash-Reports
        if l_type != "UFED":
            self.change.set(0)
            self.text.configure(text="Performing Extraction of Crash Reports")
            self.prog_text.configure(text="0%")
            self.progress.pack_forget() 
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
            self.progress.set(0)
            self.progress.pack()
            self.crash_start = threading.Thread(target=lambda: crash_report(crash_dir=".tar_tmp/Crash", change=self.change, progress=self.progress, prog_text=self.prog_text))
            self.crash_start.start()
            self.wait_variable(self.change)
            self.progress.pack_forget()
            self.prog_text.pack_forget()
            tar.add(".tar_tmp/Crash", arcname=("/Crash"), recursive=True)
            shutil.rmtree(".tar_tmp/Crash")

            
        #Gather device information as device_values.plist for UFD-ZIP
        else:
            de_va_di = self.devinfo_plist()
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
            self.text.configure(text="Calculate SHA256 hash. This may take a while.")
            self.change.set(0)
            global z_hash
            z_hash = ""
            self.prog_text.configure(text=" ")
            self.progress.pack_forget()
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
            self.progress.pack()
            self.progress.start()
            self.hashf = threading.Thread(target=lambda: self.hash_ufd(change=self.change, zipname=zipname))
            self.hashf.start()
            self.wait_variable(self.change)
            with open("Apple_" + hardware.upper() + " " + dev_name + ".ufd", "w") as ufdf:
                ufdf.write("[DeviceInfo]\nIMEI1=" + imei + "\nIMEI2=" + imei2 + "\nModel=" + product + "\nOS=" + version + "\nVendor=Apple\n\n[Dumps]\nFileDump=Apple_" + hardware.upper() + " " +
                dev_name + ".zip\n\n[ExtractionStatus]\nExtractionStatus=Success\n\n[FileDump]\nType=ZIPfolder\nZIPLogicalPath=iPhoneDump\n\n[General]\nAcquisitionTool=UFADE\nBackupPassword=12345\nConnectionType=Cable No. 210 or Original Cable\nDate=" + begin + "\nDevice=" + d_class.upper() + "\nEndTime=" + e_end + "\nExtractionNameFromXML=File System\nExtractionType=AdvancedLogical\nFullName=" +
                hardware.upper() + " " + dev_name + "\nGUID=" + udid + "\nInternalBuild=\nIsEncrypted=True\nIsEncryptedBySystem=True\nMachineName=\nModel=" + hardware.upper() + " " + dev_name + "\nUfdVer=1.2\nUnitId=\nUserName=\nVendor=Apple\nVersion=other\n\n[SHA256]\n" + zipname + "=" + z_hash.upper() + "")
            self.progress.pack_forget()

        self.text.configure(text="Backup complete!\nTrying to deactivate Backup Encryption again. \nUnlock device with PIN/PW if prompted")
        self.change.set(0)
        beep_timer = threading.Timer(13.0,self.notification)  
        beep_timer.start()
        remove_enc = threading.Thread(target=lambda: self.deactivate_encryption(change=self.change, text=self.text))
        remove_enc.start()
        self.wait_variable(self.change)
        beep_timer.cancel()   

        self.text.configure(text="Logical+ Backup completed!")
        self.after(500, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))

#Gather devinfo for plist
    def devinfo_plist(self):
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
            for key in de_va1:
                try: de_va_di.update([(key,(lockdown.get_value("",key)))])
                except: pass
            for key in de_va2:
                try: de_va_di.update([(key,(lockdown.get_value(key,"")))])
                except: pass
            return(de_va_di) 

#Perform an iTunes Backup and extract only WhatsApp files (ChatStorage.sqlite and Media folder)
    def backup_tess(self):
        if "net.whatsapp.WhatsApp" not in app_id_list and "net.whatsapp.WhatsAppSMB" not in app_id_list:
            ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
            ctk.CTkLabel(self.dynamic_frame, text="PuMA Backup", height=80, width=585, font=("standard",24), justify="left").pack(pady=20)
            self.text = ctk.CTkLabel(self.dynamic_frame, text="WhatsApp not installed on device!", width=585, height=60, font=self.stfont, anchor="w", justify="left")
            self.text.pack(anchor="center", pady=25)
            self.after(500, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AdvMenu")).pack(pady=40))   

        else:
            self.wachange = ctk.IntVar(self, 0)
            self.label1 = ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont)
            self.label1.pack(anchor="center")
            self.label2 = ctk.CTkLabel(self.dynamic_frame, text="PuMA Backup", height=80, width=585, font=("standard",24), justify="left")
            self.label2.pack(pady=20)
            if "net.whatsapp.WhatsApp" in app_id_list and "net.whatsapp.WhatsAppSMB" not in app_id_list:
                self.after(100, lambda: self.wachange.set(1))
            elif "net.whatsapp.WhatsApp" not in app_id_list and "net.whatsapp.WhatsAppSMB" in app_id_list:
                self.after(100, lambda: self.wachange.set(2))
            elif "net.whatsapp.WhatsApp" in app_id_list and "net.whatsapp.WhatsAppSMB" in app_id_list:                
                self.text = ctk.CTkLabel(self.dynamic_frame, text="Choose the Whatsapp application to extract:", width=585, height=60, font=self.stfont, anchor="w", justify="left")
                self.text.pack(anchor="center", pady=25)
                self.wa_button = ctk.CTkButton(self.dynamic_frame, text="WhatsApp", font=self.stfont, command=lambda: self.wachange.set(1))
                self.wa_button.pack(pady=10)
                self.wab_button = ctk.CTkButton(self.dynamic_frame, text="WhatsApp Business", font=self.stfont, command=lambda: self.wachange.set(2))
                self.wab_button.pack(pady=10)
                self.b_button = ctk.CTkButton(self.dynamic_frame, text="Both", font=self.stfont, command=lambda: self.wachange.set(3))
                self.b_button.pack(pady=10)
                self.backbutton = ctk.CTkButton(self.dynamic_frame, text="Back", command=lambda: [self.switch_menu("AdvMenu"), self.wachange.set(0)])
                self.backbutton.pack(anchor="e", pady=85, padx=(0,65))
            self.waitvar(self.wachange)
            if self.wachange.get() == 0:
                return()
            self.label1.pack_forget()
            self.label2.pack_forget()
            if "net.whatsapp.WhatsApp" in app_id_list and "net.whatsapp.WhatsAppSMB" in app_id_list:  
                self.text.pack_forget()
                self.wa_button.pack_forget()
                self.wab_button.pack_forget()
                self.b_button.pack_forget()
                self.backbutton.pack_forget()
            self.perf_iTunes_bu("PuMA")
            self.after(100, lambda: self.text.configure(text="Extracting WhatsApp files from backup."))
            self.prog_text = ctk.CTkLabel(self.dynamic_frame, text=" ", width=585, height=20, font=self.stfont, anchor="w", justify="left")
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
            self.progress.pack()
            self.progress.start()
            self.change = ctk.IntVar(self, 0)
            self.tess_init = threading.Thread(target=lambda: self.init_backup_decrypt(self.change))
            self.tess_init.start()
            self.waitvar(self.change)
            if self.change.get() == 1:
                self.change.set(0)
                self.tess_backup = threading.Thread(target=lambda: self.decrypt_whatsapp(self.change, self.wachange))
                self.tess_backup.start()
                self.waitvar(self.change)
            elif self.change.get() == 2:
                self.change.set(0)
                self.tess_backup_alt = threading.Thread(target=lambda: self.decrypt_whatsapp_alt(self.change, self.wachange))
                self.tess_backup_alt.start()
                self.waitvar(self.change)
            self.prog_text.pack_forget()
            self.progress.pack_forget()
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AdvMenu")).pack(pady=40))   

#SSH-Dump from given path
    def ssh_dump(self, text, scr_prt, remote_folder, user, pwd):
        try:
            text.configure(text="Starting FFS Backup")
            text.update()
            mux = usbmux.select_device()
            out = mux.connect(scr_prt)
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(sock=out, hostname='127.0.0.1', port=scr_prt, username=user, password=pwd, look_for_keys=False, allow_agent=False)
            stdin, stdout, stderr = client.exec_command(f"du -s {remote_folder}")
            remote_folder_size = [int(s) for s in stdout.read().split() if s.isdigit()][0]*512
            tar_command = f"tar --exclude *.gl --exclude '.overprovisioning_file' -cf - {remote_folder}"
            stdin, stdout, stderr = client.exec_command(tar_command)
            tar_data = stdout.channel.recv(65536)
            transferred = 0

            text.configure(text="Performing Filesystem Backup")
            text.update()
            self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
            self.prog_text.pack()
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
            self.progress.set(0)
            self.progress.pack()
            self.received_text = ctk.CTkLabel(self.dynamic_frame, text=" ", width=585, height=20, font=self.stfont, anchor="w", justify="left")
            self.received_text.pack(pady=20)

            with open(udid + "_ffs.tar", "wb") as f:
                while tar_data:
                    f.write(tar_data)
                    tar_data = stdout.channel.recv(65536)
                    transferred += len(tar_data)
                    ffs_pro = transferred / remote_folder_size
                    self.prog_text.configure(text=f"{int(ffs_pro*100)}%")
                    self.progress.set(ffs_pro)
                    self.received_text.configure(text=f"{transferred / (1024 * 1024):.2f} MB received.")
            for i in range(int(ffs_pro*100), 100):
                self.prog_text.configure(text=f"{i}%")
                self.progress.set(i/100)
                self.after(20)
            client.close()
            self.prog_text.pack_forget()
            self.progress.pack_forget()
            self.received_text.pack_forget()
            text.configure(text="Filesystem Backup complete.")
            self.change.set(1)
        except:
            text.configure(text="Error connecting to SSH. The device has to be in jailbroken state and SSH has to be installed.")
            self.change.set(1)

    def perf_jailbreak_ssh_dump(self):
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Filesystem Backup", height=80, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Provide the SSH parameters. The default values are suitable for Checkra1n and Palera1n: ", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.change = ctk.IntVar(self, 0)
        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.choose_jb_params(self.text, self.portbox, self.userbox, self.pwbox, self.pathbox))
        self.okbutton.pack(side="bottom", pady=(0,400))
        self.porttext = ctk.CTkLabel(self.dynamic_frame, text="Port: ", width=40, height=20, font=self.stfont, anchor="w", justify="left")
        self.porttext.pack(pady=(0,50), padx=(100,0), side="left")
        self.portbox = ctk.CTkEntry(self.dynamic_frame, width=80, height=20, corner_radius=0, placeholder_text="44")
        self.portbox.insert(0, string="44")
        self.portbox.pack(pady=(0,50), padx=(0,0), side="left")
        self.usertext = ctk.CTkLabel(self.dynamic_frame, text="User: ", width=40, height=20, font=self.stfont, anchor="w", justify="left")
        self.usertext.pack(pady=(0,50), padx=(10,0), side="left")
        self.userbox = ctk.CTkEntry(self.dynamic_frame, width=80, height=20, corner_radius=0, placeholder_text="root")
        self.userbox.insert(0, string="root")
        self.userbox.pack(pady=(0,50), padx=(0,0), side="left")
        self.pwtext = ctk.CTkLabel(self.dynamic_frame, text="Pass: ", width=40, height=20, font=self.stfont, anchor="w", justify="left")
        self.pwtext.pack(pady=(0,50), padx=(10,0), side="left")
        self.pwbox = ctk.CTkEntry(self.dynamic_frame, width=80, height=20, corner_radius=0, placeholder_text="alpine")
        self.pwbox.insert(0, string="alpine")
        self.pwbox.pack(pady=(0,50), padx=(0,0), side="left")
        self.pathtext = ctk.CTkLabel(self.dynamic_frame, text="Path: ", width=40, height=20, font=self.stfont, anchor="w", justify="left")
        self.pathtext.pack(pady=(0,50), padx=(10,0), side="left")
        self.pathbox = ctk.CTkEntry(self.dynamic_frame, width=80, height=20, corner_radius=0, placeholder_text="/private")
        self.pathbox.insert(0, string="/private")
        self.pathbox.pack(pady=(0,50), padx=(0,0), side="left")
        self.wait_variable(self.change)
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))   

    def choose_jb_params(self, text, portbox, userbox, pwbox, pathbox):
        scr_prt = int(portbox.get())
        user = userbox.get()
        pwd = pwbox.get()
        remote_folder = pathbox.get()
        portbox.pack_forget()
        userbox.pack_forget()
        pwbox.pack_forget()
        pathbox.pack_forget()
        self.porttext.pack_forget()
        self.usertext.pack_forget()
        self.pwtext.pack_forget()
        self.pathtext.pack_forget()
        self.okbutton.pack_forget() 
        perfssh = threading.Thread(target=lambda: self.ssh_dump(text, scr_prt, remote_folder, user, pwd))
        perfssh.start()

# Network Sniffer Display
    def show_sniffer(self):
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Capture Device Traffic", height=80, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Set the number of packets to sniff (0 is endless):", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.change = ctk.IntVar(self, 0)
        self.packetbox = ctk.CTkEntry(self.dynamic_frame, width=80, height=20, corner_radius=0, placeholder_text="0")
        self.packetbox.bind(sequence="<Return>", command=lambda x: self.call_ncapture(self.packetbox, self.okbutton, self.text, self.change))
        self.packetbox.insert(0, string="0")
        self.packetbox.pack(side="left", pady=(0,370), padx=(230,0))  
        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.call_ncapture(self.packetbox, self.okbutton, self.text, self.change))
        self.okbutton.pack(side="left", pady=(0,370), padx=(10,120))
        self.waitvar(self.change)
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AdvMenu")).pack(pady=40))   

# Call the sniffing function as a thread with provided user input
    def call_ncapture(self, packetbox, okbutton, text, change):
        self.stop_event.clear()
        packnum = packetbox.get()
        packetbox.pack_forget()
        okbutton.pack_forget()
        self.ncap = threading.Thread(target=lambda: self.network_capture(packnum, text, change))
        self.ncap.start()
        self.wait_variable(change)
        self.abort.pack_forget()

# Actually performing the sniffing process
    def network_capture(self, packnum, text, change):
        self.text.configure(text="Network sniffing in process." )
        try: 
            count = int(packnum)
            if count == 0:
                count = -1  
            serv_pcap = PcapdService(lockdown) 
            packets_generator = serv_pcap.watch(packets_count=count)
            self.abort = ctk.CTkButton(self.dynamic_frame, text="Abort", font=self.stfont, command=lambda: serv_pcap.close())
            self.abort.pack(pady=40)            
            with open(udid + ".pcap", "wb") as pcap_file:
                serv_pcap.write_to_pcap(pcap_file, packets_generator)
            text.configure(text="Sniffing process stopped. " + str(count) + " packages received." )
        except ValueError: 
            text.configure(text="Invalid input. Provide digits only.")
        except:
            text.configure(text=f"Sniffing process stopped.\nTraffic has been written to: {udid}.pcap")
        finally:
            change.set(1)
        change.set(1)
        return

# Media Extracton for Watches
    def show_media(self):
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Extract AFC-Media files", height=80, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Performing AFC Extraction of Mediafiles", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        folder = f"Media_{udid}"
        try: os.mkdir(folder)
        except: pass
        self.change = ctk.IntVar(self, 0)
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.prog_text.configure(text="0%")
        self.progress.pack()
        self.tar_media = threading.Thread(target=lambda: media_export(l_type="folder", dest=folder, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change))
        self.tar_media.start()
        self.wait_variable(self.change)
        self.text.configure(text="AFC Extraction complete.")
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        if d_class == "Watch":
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("WatchMenu")).pack(pady=40))  
        else:
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AdvMenu")).pack(pady=40)) 
### check start

    def show_report(self):
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Generate UFDR Report", height=80, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Performing AFC Extraction of Mediafiles", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.change = ctk.IntVar(self, 0)
        now = datetime.now()
        try: os.mkdir("Report")
        except: pass
        try: os.mkdir(os.path.join("Report", "files"))
        except: pass
        try: os.mkdir(os.path.join("Report", "files", "Diagnostics"))
        except: pass
        mfolder = os.path.join("Report", "files", "AFC_Media" )
        try: os.mkdir(mfolder)
        except: pass
        cfolder = os.path.join("Report", "files", "Diagnostics", "~CrashLogs")
        try: os.mkdir(cfolder)
        except: pass    
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.progress.pack()
        self.mediaexport = threading.Thread(target=lambda: media_export(l_type="folder", dest=mfolder, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change))
        self.mediaexport.start()
        self.wait_variable(self.change)
        self.change.set(0)
        self.progress.set(0)
        self.prog_text.configure(text="0%")
        self.text.configure(text="Pulling Crash Logs from the device.")
        self.crashl = threading.Thread(target=lambda: crash_report(crash_dir=cfolder, change=self.change, progress=self.progress, prog_text=self.prog_text))
        self.crashl.start()
        self.wait_variable(self.change)
        self.prog_text.configure(text="")
        self.progress.pack_forget()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
        self.progress.pack()
        self.progress.start()
        self.text.configure(text="Generating report files. This may take some time")
        self.change.set(0)
        self.text.configure(text="Pulling Crash Logs from the device.")
        self.report = threading.Thread(target=lambda: self.watch_report(text=self.text, change=self.change, progress=self.progress, prog_text=self.prog_text, now=now))
        self.report.start()
        self.wait_variable(self.change)
        self.text.configure(text="Report generation complete")
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("WatchMenu")).pack(pady=40))

    def watch_report(self, text, prog_text, progress, change, now, case_number="", case_name="", evidence_number="", examiner=""):   
        cfolder = os.path.join("Report", "files", "Diagnostics", "~CrashLogs")
        prog_text.configure(text="")
        text.configure(text="Generating report files. This may take some time.")
        progress.pack_forget()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
        self.progress.pack()
        self.progress.start()
        diagnostics = {}
        diagnostics["Diagnostics"] = DiagnosticsService(lockdown).info()
        with open(os.path.join("Report", "files", "Diagnostics", "~Diagnostics"), "wb") as file:
            plistlib.dump(diagnostics, file)

        ioreg = {}
        ior = DiagnosticsService(lockdown).ioregistry()
        if ior == None:
            ior = {}
            ior["IORegistry"] = {}
        ioreg["Diagnostics"] = ior
        with open(os.path.join("Report", "files", "Diagnostics", "~IORegistry"), "wb") as file:
            plistlib.dump(ioreg, file)

        devinfo = lockdown.all_values
        with open(os.path.join("Report", "files", "Diagnostics", "devinfo.plist"), "wb") as file:
            plistlib.dump(devinfo, file)

        de_va_di = self.devinfo_plist()
        with open(os.path.join("Report", "files", "Diagnostics", "devvalues.plist"), "wb") as file:
            plistlib.dump(de_va_di, file)

        allappsinfo = installation_proxy.InstallationProxyService(lockdown).get_apps()
        with open(os.path.join("Report", "files", "Diagnostics", "allappsinfo.plist"), "wb") as file:
            plistlib.dump(allappsinfo, file)

        allappsitunes = {}
        itunes = installation_proxy.InstallationProxyService(lockdown).browse(attributes=['CFBundleIdentifier', 'iTunesMetadata'])
        for app in itunes:
            allappsitunes[app['CFBundleIdentifier']] = app
        with open(os.path.join("Report", "files", "Diagnostics", "allappsitunes.plist"), "wb") as file:
            plistlib.dump(allappsitunes, file)

        allappsicons = {}
        icons = installation_proxy.InstallationProxyService(lockdown).browse(attributes=['CFBundleIdentifier','CFBundleIcon', 'CFBundleName'])
        for app in icons:
            icon = {}
            try:
                icon['CFBundleIcon'] = app['CFBundleIcon']
                icon['CFBundleName'] = app['CFBundleName']
            except:
                icon['CFBundleIcon'] = bytes(0)
                icon['CFBundleName'] = app['CFBundleName']
            allappsicons[app['CFBundleIdentifier']] = icon
        with open(os.path.join("Report", "files", "Diagnostics", "allappsicons.plist"), "wb") as file:
            plistlib.dump(allappsicons, file)

        allappsusage = {}
        usages = installation_proxy.InstallationProxyService(lockdown).browse(attributes=['CFBundleIdentifier','DynamicDiskUsage', 'StaticDiskUsage'])
        for app in usages:
            usage = {}
            try:
                usage['CFBundleIdentifier'] = app['CFBundleIdentifier']
                usage['DynamicDiskUsage'] = app['DynamicDiskUsage']
                usage['StaticDiskUsage'] = app['StaticDiskUsage']
            except:
                usage['CFBundleIdentifier'] = app['CFBundleIdentifier']
            allappsusage[app['CFBundleIdentifier']] = usage
        with open(os.path.join("Report", "files", "Diagnostics", "allappsusage.plist"), "wb") as file:
            plistlib.dump(allappsusage, file)

        try: os.mkdir(os.path.join("Report", "files", "Diagnostics", "~DiagnosticRelay"))
        except: pass
        try: os.mkdir(os.path.join("Report", "files", "Diagnostics", "~DiagnosticRelay", "MobileGestalt"))
        except: pass
        mg = {}
        mgval = {}
        try:
            mgval["MobileGestalt"] = DiagnosticsService(lockdown).mobilegestalt()
        except:
            status = {}
            status["Status"] = 'MobileGestaltDeprecated'
            mgval["MobileGestalt"] = status
        mg["Diagnostics"] = mgval
        mg["Status"] = "Success"
        with open(os.path.join("Report", "files", "Diagnostics", "~DiagnosticRelay", "MobileGestalt", "All.plist"), "wb") as file:
            plistlib.dump(mg, file)

        try: os.mkdir(os.path.join("Report", "files", "Applications"))
        except: pass

        appfile = installation_proxy.InstallationProxyService(lockdown).browse(attributes=['CFBundleIdentifier', 'iTunesMetadata', 'ApplicationDSID', 'ApplicationSINF', 'ApplicationType', 'CFBundleDisplayName', 'CFBundleExecutable', 'CFBundleName', 'CFBundlePackageType', 'CFBundleShortVersionString', 'CFBundleVersion', 'Container', 'GroupContainers', 'MinimumOSVersion', 'Path', 'UIDeviceFamily', 'DynamicDiskUsage', 'StaticDiskUsage', 'UIFileSharingEnabled'])
        for app in appfile:
            appname = app['CFBundleIdentifier']
            try: os.mkdir(os.path.join("Report", "files", "Applications", appname))
            except: pass
            try: 
                itunesplist = app['iTunesMetadata']
                with open(os.path.join("Report", "files", "Applications", appname, "iTunesMetadata.plist"), "wb") as file:
                    file.write(itunesplist)
            except:
                pass
            addition = {}
            try:addition['ApplicationDSID'] = app['ApplicationDSID']
            except: pass
            try: addition['ApplicationSINF'] = app['ApplicationSINF']
            except: pass
            try: addition['ApplicationType'] = app['ApplicationType']
            except: pass
            try: addition['CFBundleDisplayName'] = app['CFBundleDisplayName']
            except: pass
            try: addition['CFBundleIdentifier'] = app['CFBundleIdentifier']
            except: pass
            try: addition['CFBundleName'] = app['CFBundleName']
            except: pass
            try: addition['CFBundlePackageType'] = app['CFBundlePackageType']
            except: pass
            try: addition['CFBundleShortVersionString'] = app['CFBundleShortVersionString']
            except: pass
            try: addition['CFBundleVersion'] = app['CFBundleVersion']
            except: pass
            try: addition['Container'] = app['Container']
            except: pass
            try: addition['GroupContainers'] = app['GroupContainers']
            except: pass
            try: addition['MinimumOSVersion'] = app['MinimumOSVersion']
            except: pass
            try: addition['Path'] = app['Path']
            except: pass
            try: addition['UIDeviceFamily'] = app['UIDeviceFamily']
            except: pass
            try: addition['iTunesMetadata'] = app['iTunesMetadata']
            except: pass
            with open(os.path.join("Report", "files", "Applications", appname, "AdditionInfo.plist"), "wb") as file:
                plistlib.dump(addition, file)

            with open(os.path.join("Report", "files", "Applications", appname, "description.info"), "w") as file:
                file.write(f"Name={app['CFBundleDisplayName']}\n")
                file.write(f"Package={app['CFBundleIdentifier']}\n")
                try: file.write(f"Version={app['CFBundleVersion']}\n")
                except: file.write("Version=")
                if app['ApplicationType'] == "User":
                    file.write("IsSystem=0\n")
                else:
                    file.write("IsSystem=1\n")
                try: file.write(f"AppSize={app['StaticDiskUsage']}\n")
                except: file.write("AppSize=0\n")
                try: file.write(f"DataSize={app['DynamicDiskUsage']}\n")
                except: file.write("DataSize=0\n")
                try: file.write(f"MinimumOS={app['MinimumOSVersion']}\n")
                except: file.write(f"MinimumOS=0\n")
                try:
                    if app['UIFileSharingEnabled'] == True:            
                        file.write("FileSharing=1\n")
                except:
                    file.write("FileSharing=0\n")

            with open(os.path.join("Report", "files", "Applications", appname, "description.info.xml"), "w", encoding="UTF-8") as file:
                file.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                file.write('<Appinfo type="iOS">\n')
                file.write(f'<Name sourceValue="CFBundleDisplayName">{app['CFBundleDisplayName']}</Name>\n')
                file.write(f'<Package sourceValue="CFBundleIdentifier">{app['CFBundleIdentifier']}</Package>\n')
                file.write(f'<iOSValue sourceValue="CFBundlePackageType">{app['CFBundlePackageType']}</iOSValue>\n')
                try: file.write(f'<Version sourceValue="CFBundleVersion">{app['CFBundleVersion']}</Version>\n')
                except: file.write('<Version sourceValue="CFBundleVersion">0</Version>\n')
                file.write(f'<iOSValue sourceValue="CFBundleName">{app['CFBundleName']}</iOSValue>\n')
                try: file.write(f'<iOSValue sourceValue="Container">{app['Container']}</iOSValue>\n')
                except: file.write('<iOSValue sourceValue="Container"></iOSValue>\n')
                try: file.write(f'<iOSValue sourceValue="Path">{app['Path']}</iOSValue>\n')
                except: file.write('<iOSValue sourceValue="Path"></iOSValue>\n')
                file.write(f'<iOSValue sourceValue="ApplicationType">{app['ApplicationType']}</iOSValue>\n')
                try: file.write(f'<MinimumOS sourceValue="MinimumOS">{app['MinimumOS']}</MinimumOS>\n')
                except: file.write('<MinimumOS sourceValue="MinimumOS"></MinimumOS>\n')
                try: file.write(f'<FileSharing sourceValue="UIFileSharingEnabled">{app['UIFileSharingEnabled']}</FileSharing>\n')
                except: file.write('<FileSharing sourceValue="UIFileSharingEnabled">0</FileSharing>\n')
                try: file.write(f'<iOSValue sourceValue="ApplicationDSID">{app['ApplicationDSID']}</iOSValue>\n')
                except: file.write('<iOSValue sourceValue="ApplicationDSID">0</iOSValue>\n')
                try: file.write(f'<AppSize sourceValue="StaticDiskUsage">{app['StaticDiskUsage']}</AppSize>\n')
                except: file.write('<AppSize sourceValue="StaticDiskUsage">0</AppSize>\n')
                try: file.write(f'<DataSize sourceValue="DynamicDiskUsage">{app['DynamicDiskUsage']}</DataSize>\n')
                except: file.write('<DataSize sourceValue="DynamicDiskUsage">0</DataSize>\n')
                file.write('<CacheSize>-1</CacheSize>\n')
                file.write('</Appinfo>\n')

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

        reportid = str(str(uuid.uuid4()))
        project = ET.Element('project', {
            'xmlns': 'http://pa.cellebrite.com/report/2.0',
            'id': reportid,
            'name': f'{dev_name} - UFADE Export',
            'reportVersion': '5.0.0.0',
            'containsGarbage': 'False',
            'extractionType': 'AdvancedLogical'
            })

        source_extractions = ET.SubElement(project, 'sourceExtractions')
        ET.SubElement(source_extractions, 'extractionInfo', {
            'id': '0',
            'name': 'Logical',
            'isCustomName': 'False',
            'type': 'AdvancedLogical',
            'deviceName': '',
            'fullName': '',
            'index': '0',
            'IsPartialData': 'False'
            })
        case_information = ET.SubElement(project, 'caseInformation')
        ET.SubElement(case_information, 'field', {
            'name': 'Case number',
            'isSystem': 'True',
            'isRequired': 'True',
            'fieldType': 'CaseNumber',
            'multipleLines': 'False'
        }).text = case_number

        ET.SubElement(case_information, 'field', {
            'name': 'Case name',
            'isSystem': 'True',
            'isRequired': 'True',
            'fieldType': 'CaseName',
            'multipleLines': 'False'
        }).text = case_name

        ET.SubElement(case_information, 'field', {
            'name': 'Evidence number',
            'isSystem': 'True',
            'isRequired': 'True',
            'fieldType': 'EvidenceNumber',
            'multipleLines': 'False'
        }).text = evidence_number

        ET.SubElement(case_information, 'field', {
            'name': 'Examiner name',
            'isSystem': 'True',
            'isRequired': 'True',
            'fieldType': 'ExaminerName',
            'multipleLines': 'False'
        }).text = examiner

        metadata = ET.SubElement(project, 'metadata', {'section': 'Extraction Data'})
        ET.SubElement(metadata, 'item', {
            'name': 'DeviceInfoExtractionStartDateTime',
            'sourceExtraction': '0'
        }).text = begin

        ET.SubElement(metadata, 'item', {
            'name': 'DeviceInfoExtractionEndDateTime',
            'sourceExtraction': '0'
        }).text = e_end

        metadata_device_info = ET.SubElement(project, 'metadata', {'section': 'Device Info'})
        me_dev_info = {'Detected Manufacturer': 'Apple', 'Serial Number': snr, 'Device Name': name, 'WiFi Address': w_mac, 'Model Number': hardware + ", Model:" + mnr, 'Bluetooth Address': b_mac, 'Product Type': dev_name, 'Time Zone': d_tz, 'Unique Identifier': udid}
        for key, value in me_dev_info.items():
             ET.SubElement(metadata_device_info, 'item', {
                'id': str(uuid.uuid4()),
                'name': key,
                'sourceExtraction': '0'
            }).text = value

        afc_id = str(uuid.uuid4())
        appl_id = str(uuid.uuid4())
        diag_id = str(uuid.uuid4())
        
        tagged_files = ET.SubElement(project, 'taggedFiles')
        for file_info in filedict:
            file_elem = ET.SubElement(tagged_files, 'file', {
                'fs': 'AFC_Media',
                'fsid': afc_id,
                'path': filedict[file_info]['metadata']['Local Path'],
                'size': filedict[file_info]['size'],
                'id': str(uuid.uuid4()),
                'extractionId': "0",
                'embedded': "false",
                'isrelated': "False"
            })
            access_info = ET.SubElement(file_elem, 'accessInfo')
            for timestamp_name, timestamp_value in filedict[file_info]['accessInfo'].items():
                ET.SubElement(access_info, 'timestamp', {'name': timestamp_name}).text = timestamp_value
            metadata_file = ET.SubElement(file_elem, 'metadata', {'section': 'File'})
            for item_name, item_value in filedict[file_info]['metadata'].items():
                ET.SubElement(metadata_file, 'item', {'name': item_name}).text = item_value
            metadata_metadata = ET.SubElement(file_elem, 'metadata', {'section': 'MetaData'})
            if "Exif" in filedict[file_info]:
                for item_name, item_value in filedict[file_info]["Exif"].items():
                    item_attributes = {'name': item_name}
                    item_attributes['group'] = "EXIF"
                    ET.SubElement(metadata_metadata, 'item', item_attributes).text = item_value


        rough_string = ET.tostring(project, 'utf-8')
        reparsed = minidom.parseString(rough_string)
        xml_str = reparsed.toprettyxml(indent="  ", encoding="UTF-8")

        with open(os.path.join("Report", "report.xml"), "w", encoding="UTF-8") as f:
            #f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write(xml_str)
        change.set(1)

# Try to mount a suitable developerdiskimage
    def mount_developer(self, change, text):
        global developer
        global lockdown
        d_images = {4:[2,3], 5:[0,1], 6:[0,1], 7:[0,1], 8:[0,1,2,3,4], 9:[0,1,2,3],
                    10:[0,1,2,3], 11:[0,1,2,3,4], 12:[0,1,2,3,4], 13:[0,1,2,3,4,5,7],
                    14:[0,1,2,4,5,6,7,7.1,8], 15:[0,1,2,3,3.1,4,5,6,6.1,7],
                    16:[0,1,2,3,3.1,4,4.1,5,6,7]}
        try:
            if DeveloperDiskImageMounter(lockdown).copy_devices() != []:
                developer = True
                change.set(1)
                return("developer")
        except exceptions.MessageNotSupportedError:
            text.configure(text="Something went wrong. Make sure the device is unlocked.")
            change.set(1)
            return("nope")
        except:
            pass
        try:
            if lockdown.developer_mode_status == True:
                pass
            else:
                self.choose = ctk.BooleanVar(self, False)
                text.configure(text="The device has to be rebooted in order to activate the developer mode.\n(Deactivate the PIN/PW before you proceed)\n\nDo you want to restart the device?")
                self.yesb = ctk.CTkButton(self.dynamic_frame, text="YES", font=self.stfont, command=lambda: self.choose.set(True))
                self.yesb.pack(side="left", pady=(0,350), padx=140)
                self.nob = ctk.CTkButton(self.dynamic_frame, text="NO", font=self.stfont, command=lambda: self.choose.set(False))
                self.nob.pack(side="left", pady=(0,350))    
                self.wait_variable(self.choose)  
                if self.choose.get() == True:
                    self.yesb.pack_forget()
                    self.nob.pack_forget()
                    text.configure(text="Wait for the device to reboot.\nUnlock it and confirm the activation of the developer mode.\nAfter this, press \"OK\".")
                    try:
                        amfi_dev = threading.Thread(target=lambda: AmfiService(lockdown).enable_developer_mode(enable_post_restart=True))
                        amfi_dev.start()
                        self.choose.set(False)
                        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.choose.set(True))
                        self.okbutton.pack()
                        self.wait_variable(self.choose)
                        self.okbutton.pack_forget()
                        #lockdown = create_using_usbmux()
                        self.after(50)
                        #if DeveloperDiskImageMounter(lockdown).copy_devices() == []:
                        if lockdown.developer_mode_status != True:
                            text.configure(text="Uh-Oh, an error was raised.\nWait for the device to reboot and try again.")
                            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
                            return
                        else:
                            pass
                    except:
                        text.configure(text="Uh-Oh, an error was raised. Please remove the PIN/PW and try again")
                        developer = False
                        change.set(1)
                        return
                else:
                    self.yesb.pack_forget()
                    self.nob.pack_forget()
                    developer = False
                    change.set(1)
                    return
        except:
            pass
        if int(version.split(".")[0]) < 17:
            try: 
                self.after(100)
                text.configure(text=" ", anchor="nw", justify="left")
                text.update()
                self.after(1000)
                info = ("Looking for version " + version)
                text.configure(text=info)
                self.after(1000)
                lockdown = create_using_usbmux()
                DeveloperDiskImageMounter(lockdown).mount(image=os.path.join(os.path.dirname(__file__),"ufade_developer", "Developer", version, "DeveloperDiskImage.dmg"), signature=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", version, "DeveloperDiskImage.dmg.signature"))
                developer = True
                change.set(1)
                return("developer")   
            except:
                info = info + "\nVersion " + version + " not found"
                text.configure(text=info)
                self.after(1000)
                v = version.split(".")
                v_check = np.array(d_images[int(v[0])])
                v_diff = np.absolute(v_check - int(v[1]))
                index = v_diff.argmin()
                ver = str(v[0]) + "." + str(d_images[int(v[0])][index])
            finally:
                if int(v[0]) <= 12 or DeveloperDiskImageMounter(lockdown).copy_devices() == []:
                    self.after(1000)
                    info = info + "\nClosest version is " + ver
                    text.configure(text=info)
                    lockdown = create_using_usbmux()
                    self.after(1000)
                    try:
                        DeveloperDiskImageMounter(lockdown).mount(image=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", ver, "DeveloperDiskImage.dmg"), signature=os.path.join(os.path.dirname(__file__),"ufade_developer", "Developer", ver, "DeveloperDiskImage.dmg.signature"))
                        info = info + "\nVersion: " + ver + " was used"
                        text.configure(text=info)
                        self.after(1000)
                        developer = True
                        change.set(1)
                        return("developer")
                    except exceptions.AlreadyMountedError:
                        developer = True
                        change.set(1)
                        return("developer")            
                    except: 
                        for i in range(index)[::-1]:
                            ver = str(v[0]) + "." + str(d_images[int(v[0])][i])
                            try:
                                DeveloperDiskImageMounter(lockdown).mount(image=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", ver, "DeveloperDiskImage.dmg"), signature=os.path.join(os.path.dirname(__file__),"ufade_developer", "Developer", ver, "DeveloperDiskImage.dmg.signature"))
                                info = info + "\nVersion: " + ver + " was used"
                                text.configure(text=info)
                                self.after(1000)
                                break
                            except:
                                pass
                        if int(v[0]) <= 12:
                            developer = True
                            change.set(1)
                            return("developer")
                        else:
                            pass
                        if DeveloperDiskImageMounter(lockdown).copy_devices() == []:
                            text.configure(text="DeveloperDiskImage not loaded")
                            developer = False
                        else:
                            text.configure(text="DeveloperDiskImage loaded")
                            developer = True
                            change.set(1)
                            return("developer")
                    
                else:
                    text.configure(text="DeveloperDiskImage loaded")
                    developer = True
                    change.set(1)
                    return("developer")
        else:
            developer = True
            change.set(1)
            return("developer")
            """
            try:
                self.after(1000)
                text.configure(text="Mounting personalized image.")
                PersonalizedImageMounter(lockdown).mount(image=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", "Xcode_iOS_DDI_Personalized", "Image.dmg"), build_manifest=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", "Xcode_iOS_DDI_Personalized", "BuildManifest.plist"), trust_cache=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", "Xcode_iOS_DDI_Personalized", "Image.dmg.trustcache"))
                developer = True
                text.configure(text="Personalized image mounted.")
                change.set(1)
                return("developer")
            except exceptions.AlreadyMountedError:
                developer = True
                change.set(1)
                return("developer")
            except:
                self.after(1000)
                text.configure(text="DeveloperDiskImage not loaded")
                developer = False
                change.set(1)
                return("nope")
            """


    def developer_options(self):
        self.change = ctk.IntVar(self, 0)
        global developer
        global lockdown
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Developer Options", height=80, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Checking developer status.", width=585, height=100, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        try:
            if len(os.listdir(os.path.join(os.path.dirname(__file__),"ufade_developer"))) != 0:
                pass
            else:
                self.text.configure(text="Directory \"ufade_developer\" is empty.\nPlease clone the submodule:\n\ngit submodule init\ngit submodule update")
                self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
                return 
        except:
            self.text.configure(text="Directory \"ufade_developer\" not found.\nPlease clone the submodule:\n\ngit submodule init\ngit submodule update")
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
            return

        #if int(version.split(".")[0]) >= 17:
        #    self.text.configure(text="Devices with iOS 17 and up aren't currently supported in this Version of UFADE.\nTry the CLI Version instead")
        #    self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
        #    return
        #else:
        #    pass

        if int(version.split(".")[0]) >= 17:
            self.chk_tun = threading.Thread(target=lambda: self.check_tun(self.change))
            self.chk_tun.start()
            self.wait_variable(self.change)
            self.change.set(0)
            if self.tun == None:
                self.text.configure(text="To use developer options on devices with iOS >= 17 a tunnel has to be created.\nThis requires administrative privileges. Do you want to continue?")
                self.choose = ctk.BooleanVar(self, False)
                self.yesb = ctk.CTkButton(self.dynamic_frame, text="YES", font=self.stfont, command=lambda: self.choose.set(True))
                self.yesb.pack(side="left", pady=(0,350), padx=140)
                self.nob = ctk.CTkButton(self.dynamic_frame, text="NO", font=self.stfont, command=lambda: self.choose.set(False))
                self.nob.pack(side="left", pady=(0,350))    
                self.wait_variable(self.choose)                             
                if self.choose.get() == True:
                    self.yesb.pack_forget()
                    self.nob.pack_forget() 
                    self.change.set(0)
                    self.dev17 = threading.Thread(target=lambda: self.run_ios17_developer(self.change)) 
                    self.dev17.start()
                    self.wait_variable(self.change)
                else:
                    self.show_main_menu()
                    return
                    #process = run(["sudo", "-E", "python3", "-m", "pymobiledevice3", "remote", "tunneld", "-d"])
            else: 
                pass
        else:
            pass

        if developer == True:
            try:
                if int(version.split(".")[0]) >= 17:
                    lockdown = get_tunneld_devices()[0]
                else:
                    lockdown = create_using_usbmux()
                dvt = DvtSecureSocketProxyService(lockdown)
                dvt.__enter__()
            except:
                if int(version.split(".")[0]) >= 17:
                    try: PersonalizedImageMounter(lockdown).umount()
                    except: pass
                else:
                    try: DeveloperDiskImageMounter(lockdown).umount()
                    except: pass
                self.text.configure(text="Error. Try again.")
                developer = False
                self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
                return
            finally:
                if developer == True:
                    self.switch_menu("DevMenu")
                else:
                    pass
        else:
            self.change.set(0)
            self.start_developer = threading.Thread(target=lambda:self.mount_developer(self.change, self.text))
            self.start_developer.start()
            self.wait_variable(self.change)
            if developer == True:
                if int(version.split(".")[0]) >= 17:
                    try:
                        lockdown = get_tunneld_devices()[0]
                    except:
                        lockdown.connect()
                else:
                    lockdown = create_using_usbmux()
                #dvt = DvtSecureSocketProxyService(lockdown)
                #dvt.__enter__()
                self.switch_menu("DevMenu")
            else:
                self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))

    def check_tun(self, change):
        try: 
            self.tun = get_tunneld_devices()
            if self.tun == []:
                self.tun = None
        except:
            self.tun = None
        finally:
            change.set(1)

# Try to open a tun device
    def run_ios17_developer(self, change):
        if platform.uname().system == 'Linux':            
            #self.waitl = ctk.IntVar(self, 0)
            script = create_linux_shell_script()
            self.run_linux_script(script, change)
            self.wait_variable(change)
            print("Developer script run")
        else:
            if platform.uname().system == 'Windows':
                from subprocess import CREATE_NO_WINDOW, CREATE_NEW_CONSOLE
                try:
                    #Popen(["python", "-m", "pymobiledevice3", "remote", "tunneld"], creationflags=CREATE_NO_WINDOW)
                    #tunneld_win(host=TUNNELD_DEFAULT_ADDRESS[0], port=TUNNELD_DEFAULT_ADDRESS[1], daemonize=False, protocol=TunnelProtocol.QUIC.value, usb=True, wifi=False, usbmux=True, mobdev2=True)
                    self.tunnel_win = threading.Thread(target=self.wintunnel)
                    self.tunnel_win.daemon = True
                    self.tunnel_win.start()
                    self.text.configure(text="Opening tunnel. This may take some time.")
                    while True:
                        try:
                            tun = get_tunneld_devices()
                        except:
                            tun = []
                        if tun != []:
                            break
                        if self.tunnel_win.is_alive() != True:
                            raise BaseException()
                except:
                    self.text.configure(text="Couldn't create a tunnel. Try again.\nYou have to run UFADE as administrator for this.")
                    self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
                    change.set(1)
                    return
            elif platform.uname().system == 'Darwin':
                self.waitm = ctk.IntVar(self, 0)
                self.mac_os_17 = threading.Thread(target=lambda: self.macos_dev17(self.waitm))
                self.mac_os_17.start()
                self.wait_variable(self.waitm)
                if self.waitm.get() == 1:
                    while True:
                        try:
                            tun = get_tunneld_devices()
                        except:
                            tun = []
                        if tun != []:
                            break
                else:
                    pass
        change.set(1)

    def wintunnel(self):
        try:
            if not get_os_utils().is_admin:
                raise exceptions.AccessDeniedError()
            else:
                tunnel_win()
            #remote.cli_tunneld()
        except:
            return

    def run_linux_script(self, script, waitl):
        try:
            run(["pkexec", script])
            waitl.set(1)
        except:
            self.text.configure(text="Couldn't create a tunnel. Try again.")
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
            waitl.set(2)
            return

    def macos_dev17(self, change):
        try:
            run(["osascript", "-e", 'do shell script \"python3 -m pymobiledevice3 remote tunneld -d\" with administrator privileges'])
            change.set(1)
        except:
            self.text.configure(text="Couldn't create a tunnel. Try again.")
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
            change.set(2)
            return

# Device screenshot
    def screen_device(self, dvt):
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Take Screenshots", height=40, width=585, font=("standard",24), justify="left").pack(pady=10)
        self.shotframe = ctk.CTkFrame(self.dynamic_frame, width=400, corner_radius=0, fg_color="transparent")
        self.textframe = ctk.CTkFrame(self.dynamic_frame, width=200, corner_radius=0, fg_color="transparent")
        self.shotframe.pack(side="left", pady=20, padx=40, fill="y", expand=True)
        self.textframe.pack(side="left", pady=20, fill="both", expand=True)
        self.placeholder_image = ctk.CTkImage(dark_image=Image.open(os.path.join(os.path.dirname(__file__), "assets" , "screen_ufade.png")), size=(240, 426))
        self.imglabel = ctk.CTkLabel(self.shotframe, image=self.placeholder_image, text=" ", width=240, height=426, font=self.stfont, anchor="w", justify="left")
        self.imglabel.pack()
        try: os.mkdir("screenshots")
        except: pass
        self.shotbutton = ctk.CTkButton(self.textframe, text="Screenshot", font=self.stfont, command=lambda: self.shotthread(dvt, self.imglabel, self.namefield))
        self.shotbutton.pack(pady=20, ipadx=0, anchor="w")
        self.abortbutton = ctk.CTkButton(self.textframe, text="Back", font=self.stfont, command=lambda: self.switch_menu("DevMenu"))
        self.abortbutton.pack(pady=5, ipadx=0, anchor="w")
        self.namefield = ctk.CTkLabel(self.textframe, text=" ", width=300, height=100, font=self.stfont, anchor="w", justify="left")
        self.namefield.pack(anchor="w", pady=10)

    def shotthread(self, dvt, imglabel, namefield):
        self.doshot = threading.Thread(target=lambda: self.shot(dvt, self.imglabel, self.namefield))
        self.doshot.start()

    def shot(self, dvt, imglabel, namefield):
        hsize = 426
        try:
            png = Screenshot(dvt).get_screenshot()
        except: 
            png = ScreenshotService(lockdown).take_screenshot()
        png_bytes = BytesIO()
        png_bytes.write(png)
        shot = Image.open(png_bytes)
        hperc = (hsize/float(shot.size[1]))
        wsize = int((float(shot.size[0])*float(hperc)))
        if wsize > 300:
            wsize = 300
            wperc = (wsize/float(shot.size[0]))
            hsize = int((float(shot.size[1])*float(wperc)))
        screensh = ctk.CTkImage(dark_image=shot, size=(wsize, hsize))
        imglabel.configure(image=screensh)
        hash_sha256 = hashlib.sha256(png).hexdigest()
        name = hardware + "_" + str(datetime.now().strftime("%m_%d_%Y_%H_%M_%S"))
        filename = name + ".png"
        hashname = name + ".txt"
        with open(os.path.join("screenshots", filename), "wb") as file:
            file.write(png)
        with open(os.path.join("screenshots", hashname), "w") as hash_file:
            hash_file.write(hash_sha256)
        namefield.configure(text=f"Screenshot saved as:\n{filename}\nHash saved as:\n{hashname}")

    def chat_shotloop(self, dvt):
        try: os.mkdir("screenshots")
        except: pass
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Chat Capture", height=40, width=585, font=("standard",24), justify="left").pack(pady=10)
        self.shotframe = ctk.CTkFrame(self.dynamic_frame, width=400, corner_radius=0, fg_color="transparent")
        self.textframe = ctk.CTkFrame(self.dynamic_frame, width=200, corner_radius=0, fg_color="transparent")
        self.shotframe.pack(side="left", pady=20, padx=40, fill="y", expand=True)
        self.textframe.pack(side="left", pady=20, fill="both", expand=True)
        self.placeholder_image = ctk.CTkImage(dark_image=Image.open(os.path.join(os.path.dirname(__file__), "assets" , "screen_ufade.png")), size=(240, 426))
        self.imglabel = ctk.CTkLabel(self.shotframe, image=self.placeholder_image, text=" ", width=240, height=426, font=self.stfont, anchor="w", justify="left")
        self.imglabel.pack()
        self.text = ctk.CTkLabel(self.textframe, text="Open the chat application and the chat\nyou want to capture, enter the name of\nthe chosen chat in the given fields", width=300, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="w")
        self.appbox = ctk.CTkEntry(self.textframe, width=140, height=20, corner_radius=0, placeholder_text="name of the app")
        self.appbox.pack(pady=10, ipadx=0, anchor="w")
        self.chatbox = ctk.CTkEntry(self.textframe, width=140, height=20, corner_radius=0, placeholder_text="name of the chat")
        self.chatbox.pack(pady=10, ipadx=0, anchor="w")
        self.upbutton = ctk.CTkButton(self.textframe, text="↑ Up", font=self.stfont, command=lambda: self.chatshotthread(dvt, app_name=self.appbox.get(), chat_name=self.chatbox.get(), direction="up", imglabel=self.imglabel, namefield=self.namefield, text=self.text))
        self.upbutton.pack(pady=10, ipadx=0, anchor="w")
        self.downbutton = ctk.CTkButton(self.textframe, text="↓ Down", font=self.stfont, command=lambda: self.chatshotthread(dvt, app_name=self.appbox.get(), chat_name=self.chatbox.get(), direction="down", imglabel=self.imglabel, namefield=self.namefield, text=self.text))
        self.downbutton.pack(pady=10, ipadx=0, anchor="w")
        self.breakbutton = ctk.CTkButton(self.textframe, text="Cancel Loop", fg_color="#8c2c27", font=self.stfont, command=self.breakshotloop)
        self.breakbutton.pack(pady=10, ipadx=0, anchor="w")
        self.abortbutton = ctk.CTkButton(self.textframe, text="Back", font=self.stfont, command=lambda: self.switch_menu("DevMenu"))
        self.abortbutton.pack(pady=10, ipadx=0, anchor="w")
        self.namefield = ctk.CTkLabel(self.textframe, text=" ", width=300, height=60, font=self.stfont, anchor="w", justify="left")
        self.namefield.pack(anchor="w", pady=5)


    def chatshotthread(self, dvt, app_name, chat_name, direction, imglabel, namefield, text):
        ab_count = 0
        sc_count = 0
        self.upbutton.configure(state="disabled")
        self.downbutton.configure(state="disabled")
        self.abortbutton.configure(state="disabled")
        self.stop_event.clear()
        self.doshot = threading.Thread(target=lambda: self.shotloop(dvt, app_name, chat_name, ab_count, sc_count, direction, imglabel, namefield, text, first=True))
        self.doshot.start()
        
    
    def breakshotloop(self):
        self.stop_event.set()
    
    def shotloop(self, dvt, app_name, chat_name, ab_count, sc_count, direction, imglabel, namefield, text, png=None, first=False):
        AccessibilityAudit(lockdown).set_show_visuals(False)
        name = chat_name + "_" + str(datetime.now().strftime("%m_%d_%Y_%H_%M_%S"))
        filename = name + ".png"
        hashname = name + ".txt"
        hsize = 426
        if direction == "down":
            ch_direction = Direction.Next
        else:
            ch_direction = Direction.Previous
        if text != None:
            text.configure(text="Chat capture is running.")
        if first != False:
            try: os.mkdir(os.path.join("screenshots", app_name))
            except: pass
            try: os.mkdir(os.path.join("screenshots", app_name, chat_name))
            except: pass
            png = Screenshot(dvt).get_screenshot()
            png_bytes = BytesIO()
            png_bytes.write(png)
            shot = Image.open(png_bytes)
            hperc = (hsize/float(shot.size[1]))
            wsize = int((float(shot.size[0])*float(hperc)))
            if wsize > 300:
                wsize = 300
                wperc = (wsize/float(shot.size[0]))
                hsize = int((float(shot.size[1])*float(wperc)))
            screensh = ctk.CTkImage(dark_image=shot, size=(wsize, hsize))
            imglabel.configure(image=screensh)
            with open(os.path.join("screenshots", app_name, chat_name, filename), "wb") as file:
                file.write(png)
            hash_sha256 = hashlib.sha256(png).hexdigest()
            with open(os.path.join("screenshots", app_name, chat_name, hashname), "w") as hash_file:
                hash_file.write(hash_sha256)
            namefield.configure(text=f"Screenshot saved as:\n{filename}\nHash saved as:\n{hashname}")
            self.shotloop(dvt, app_name, chat_name, ab_count, sc_count, direction, imglabel, namefield, png=png, text=text)
        else:
            while not self.stop_event.is_set():
                if ab_count >= 4:
                    text.configure(text="Chat loop finished.")
                    self.upbutton.configure(state="enabled")
                    self.downbutton.configure(state="enabled")
                    self.abortbutton.configure(state="enabled")
                    self.stop_event.set()
                    return
                else:
                    prev = png
                    AccessibilityAudit(lockdown).move_focus(ch_direction)
                    AccessibilityAudit(lockdown).set_show_visuals(False)
                    time.sleep(0.3)
                    png = Screenshot(dvt).get_screenshot()
                    if png != prev:
                        png_bytes = BytesIO()
                        png_bytes.write(png)
                        shot = Image.open(png_bytes)
                        hperc = (hsize/float(shot.size[1]))
                        wsize = int((float(shot.size[0])*float(hperc)))
                        if wsize > 300:
                            wsize = 300
                            wperc = (wsize/float(shot.size[0]))
                            hsize = int((float(shot.size[1])*float(wperc)))
                        screensh = ctk.CTkImage(dark_image=shot, size=(wsize, hsize))
                        imglabel.configure(image=screensh)
                        
                        with open(os.path.join("screenshots", app_name, chat_name, filename) + ".png", "wb") as file:
                            file.write(png)
                        hash_sha256 = hashlib.sha256(png).hexdigest()
                        with open(os.path.join("screenshots", app_name, chat_name, hashname), "w") as hash_file:
                            hash_file.write(hash_sha256)
                        namefield.configure(text=f"Screenshot saved as:\n{filename}\nHash saved as:\n{hashname}")
                        sc_count += 1
                        ab_count = 0
                    else:
                        if sc_count > 3:
                            ab_count += 1
                        else:
                            pass
                    self.shotloop(dvt, app_name, chat_name, ab_count, sc_count, direction, imglabel, namefield, png=png, text=text)
            text.configure(text="Chat loop stopped.")
            self.upbutton.configure(state="enabled")
            self.downbutton.configure(state="enabled")
            self.abortbutton.configure(state="enabled")
            AccessibilityAudit(lockdown).set_show_visuals(False)
            raise SystemExit
            return("interrupt")
    

# Fileloop window
    def show_fileloop(self, dvt):
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Filesystem content", height=80, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Creating a filesystem-list. This will take a while.", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack() 
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.progress.pack()
        self.folder_text = ctk.CTkLabel(self.dynamic_frame, text="Folder: ", width=585, height=40, font=self.stfont, anchor="w", justify="left")
        self.folder_text.pack()
        self.waitls = ctk.IntVar(self, 0)
        self.dev_ls = threading.Thread(target=lambda: self.call_fileloop(dvt, self.waitls, self.prog_text, self.progress, self.folder_text))
        self.dev_ls.start()
        self.wait_variable(self.waitls)
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        self.folder_text.pack_forget()
        self.text.configure(text="Creation of filesystem-list complete.")
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("DevMenu")).pack(pady=40))

# Call the fileloop and write the output to a file
    def call_fileloop(self, dvt, waitls, prog_text, progress, folder_text):
        folders = []
        for line in DeviceInfo(dvt).ls("/"):
            folders.append(line)
        fcount = len(folders)
        cnt = 0
        pathlist = []
        pathlist = fileloop(dvt, "/var", pathlist, fcount, cnt, folder_text, progress, prog_text)
        with open(udid + "_var_filesystem.txt", "w") as files:
            for line in pathlist:
                files.write("\n" + line)
        prog_text.configure(text="100%")
        progress.set(1)
        waitls.set(1)

    def call_unmount(self):
        global developer
        ctk.CTkLabel(self.dynamic_frame, text="UFADE by Christian Peter", text_color="#3f3f3f", height=40, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Unmounting DeveloperDiskImage", height=80, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Trying to unmount the image.", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.change = ctk.IntVar(self, 0)
        if int(version.split(".")[0]) < 14:
            self.text.configure(text="Unmount not possible on devices with iOS < 14.0.\nReboot the device to unmount the image. ")
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("DevMenu")).pack(pady=40))
            return
        else:
            try:
                unmount_timer = threading.Timer(6.0, unmount_abort_timer)
                unmount_timer.start()
                umount = threading.Thread(target=lambda: unmount_developer(self.text, self.change))
                umount.start()
                self.wait_variable(self.change)
                unmount_timer.cancel()
                developer = False
            except:
                pass
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))

def unmount_abort_timer():
    raise exceptions.UnsupportedCommandError()

def unmount_developer(text, change):
    try:
        if int(version.split(".")[0]) >= 17:
            PersonalizedImageMounter(lockdown).umount()
        else:
            DeveloperDiskImageMounter(lockdown).umount()
        developer = False
        text.configure(text="DeveloperDiskImage unmounted.")
        change.set(1)
    except: 
        text.configure(text="DeveloperDiskImage could not be unmounted. Restart the device to unmount.")
        developer = True
        change.set(1)
        pass

# Developer Mode filesystem-"ls"-loop
def fileloop(dvt, start, lista, fcount, cnt, folder_text, progress, prog_text):
    pathlist = lista
    try: 
        next = DeviceInfo(dvt).ls(start)
        for line in next:
            next_path = (start + "/" + line)
            if len(next_path.split("/")) == 3:
                cnt += 1
                fpro = int(44*(cnt/fcount))%100
                prog_text.configure(text=f"{fpro}%")
                progress.set(fpro/100)
                folder_text.configure(text="Folder: " + next_path)
            if next_path in pathlist:
                break
            else:
                pathlist.append(next_path)
                fileloop(dvt, next_path, pathlist, fcount, cnt, folder_text, progress, prog_text) 
    except: 
        pass
    finally:
        return(pathlist)

# Pull Media-files
def media_export(l_type, dest="Media", archive=None, text=None, prog_text=None, progress=None, change=None):
    media_list = []
    tar = archive
    zip = archive
    text.configure(text="Performing AFC Extraction of Mediafiles")
    text.update()
    for line in AfcService(lockdown).listdir("/"):
            media_list.append(line)
    if l_type != "folder":
        media_list.remove("DCIM")                                                                                         #get amount of lines (files and folders) in media root
    media_count = len(media_list)
    try: os.mkdir(dest)
    except: pass
    m_nr = 0
    for entry in media_list:
        m_nr += 1
        mpro = int(100*(m_nr/media_count))
        prog_text.configure(text=f"{mpro}%")
        progress.set(mpro/100)
        prog_text.update()
        progress.update()
        try:
            if d_class == "Watch":
                pull(self=AfcService(lockdown),relative_src=entry, dst=dest, fdict=True)
            else:
                if l_type == "folder":
                    pull(self=AfcService(lockdown),relative_src=entry, dst=dest, fdict=True)
                else:
                    pull(self=AfcService(lockdown),relative_src=entry, dst=dest, fdict=False)
            if l_type != "folder":
                file_path = os.path.join(dest, entry)                                                              #get the files and folders shared over AFC
                if l_type != "UFED":
                    tar.add(file_path, arcname=os.path.join("Media/", entry), recursive=True)                                   #add the file/folder to the TAR
                else:
                    if os.path.isfile(file_path):
                        zip.write(file_path, arcname=os.path.join("iPhoneDump/AFC Service/", entry))                            #add the file/folder to the ZIP
                    elif os.path.isdir(file_path):
                        for root, dirs, files in os.walk(dest):
                            for file in files:
                                source_file = os.path.join(root, file)
                                filename = os.path.relpath(source_file, dest)
                                zip.write(source_file, arcname=os.path.join("iPhoneDump/AFC Service/", filename))
                try: os.remove(file_path)
                except: shutil.rmtree(file_path)
            else:
                pass
        except:
            pass

    if l_type == "folder":
        with open(f"afc_files_{udid}.json", "w") as file:
            json.dump(filedict, file)
    else:
        pass
    change.set(1)   
    return(archive)    


# Pull crash logs
def crash_report(crash_dir, change, progress, prog_text):
    crash_count = 0
    crash_list = []
    for entry in CrashReportsManager(lockdown).ls(""):
        crash_list.append(entry)
        crash_count += 1           
    try: os.mkdir(crash_dir)
    except: pass
    c_nr = 0
    for entry in crash_list:
        c_nr += 1
        try: 
            AfcService(lockdown, service_name="com.apple.crashreportcopymobile").pull(relative_src=entry, dst=crash_dir, src_dir="")
        except: 
            pass
        cpro = c_nr/crash_count
        progress.set(cpro)
        prog_text.configure(text=f"{int(cpro*100)}%")
        progress.update()
        prog_text.update()
    change.set(1)


def save_info():
    file = open("device_" + udid + ".txt", "w")
    file.write("## DEVICE ##\n\n" + "Model-Nr:   " + dev_name + "\nDev-Name:   " + name + "\nHardware:   " + hardware + ", " + mnr + "\nProduct:    " + product +
        "\nSoftware:   " + version + "\nBuild-Nr:   " + build + "\nLanguage:   " + language + "\nSerialnr:   " + snr + "\nMLB-snr:    " + mlbsnr +
        "\nWifi MAC:   " + w_mac + "\nBT-MAC:     " + b_mac + "\nCapacity:   " + disk + "0 GB" + "\nFree Space: " + free + " GB" +
        "\nUDID :      " + udid + "\nECID :      " + ecid + "\nIMEI :      " + imei + "\nIMEI2:      " + imei2)    
    
    global number
    try: 
        number = lockdown.get_value(key="PhoneNumber")
        if number == None:
            number = ""
    except: number = ""
    if number != "":
        file.write("\n\nLast Number: " + number)

    if comp != []:
        file.write("\n\n## COMPANION DEVICES (e.g. Watches) ##")
        try:
            for entry in comp:
                file.write("\nUDID: " + entry)
        except:
            pass

    #SIM-Info
    global all
    try: 
        all = lockdown.all_values.get("CarrierBundleInfoArray")
        if all == None:
            all = ""
    except: 
        all = ""
    if all != "":
        for entry in all:
            if entry["Slot"] == "kOne":
                stype = "SIM"
            else:
                stype = "eSIM"
            try: file.write("\n\n## SIM-Info ##\n\nICCID:  " + entry["IntegratedCircuitCardIdentity"] + 
                                    "\nIMSI:   " + entry["InternationalMobileSubscriberIdentity"] + 
                                    "\nMCC:    " + entry["MCC"] + 
                                    "\nMNC:    " + entry["MNC"] +
                                    "\nType:   " + stype)
            except: pass
    
    #Save user-installed Apps to txt
    try: l = str(len(max(app_id_list, key=len)))  
    except: l = 40 
    file.write("\n\n" + "## Installed Apps (by user) [App, shared documents] ## \n")
    for app in app_id_list:
        try: 
            apps.get(app)['UIFileSharingEnabled']
            sharing = 'yes'
        except:
            sharing = 'no'
        file.write("\n" + '{:{l}}'.format(app, l=l) + "\t [" + sharing + "]")

    file.close()    

def check_device():
    try:
        lockdown = create_using_usbmux(autopair=False)
    except:
        lockdown = None
    return(lockdown)

def pair_device(paired):
    global lockdown
    lockdown_unpaired = lockdown
    try:
        lockdown = create_using_usbmux()
        global ispaired
        ispaired = True
        paired.set(True) 
    except:
        lockdown = lockdown_unpaired
        paired.set(False)
    return(lockdown)

# Get device information #
def dev_data():
    if lockdown != None:
        global d_class 
        d_class= lockdown.get_value("","DeviceClass")
        global dev_name
        dev_name = lockdown.display_name
        global hardware
        hardware = lockdown.hardware_model
        global product
        product = lockdown.product_type
        global udid
        udid = lockdown.udid
        global ecid
        ecid = str(lockdown.ecid)
        global version
        version = lockdown.product_version
        global w_mac 
        w_mac = lockdown.wifi_mac_address
        global name
        name =  lockdown.get_value("","DeviceName")
        global build
        build = lockdown.get_value("","BuildVersion")
        if ispaired == True:
            global imei
            global imei2
            try: imei = lockdown.get_value("","InternationalMobileEquipmentIdentity")
            except: imei = " "
            try: imei2 = lockdown.get_value("","InternationalMobileEquipmentIdentity2")
            except: imei2 = " "
            global snr 
            snr = lockdown.get_value("","SerialNumber")
            global mlbsnr 
            mlbsnr = lockdown.get_value("","MLBSerialNumber")
            global d_tz 
            d_tz = lockdown.get_value("","TimeZone")
            global b_mac
            b_mac = lockdown.get_value("","BluetoothAddress")
            global mnr
            mnr = lockdown.get_value("", "ModelNumber")
            global disk1 
            disk1 = lockdown.get_value("com.apple.disk_usage","TotalDiskCapacity")/1000000000
            global disk 
            disk = str(round(disk1,2))
            global free1 
            free1 = lockdown.get_value("com.apple.disk_usage","AmountDataAvailable")/1000000000
            global free 
            free = str(round(free1,2))
            global used1 
            used1 = disk1 - free1
            global used 
            used = str(round(used1,2))
            global graph_progress 
            graph_progress = "" + "▓" * int(26/100*(100/disk1*used1)) + "░" * int(26/100*(100/disk1*free1)) + ""
            global language
            language = lockdown.language
            global comp
            if d_class != "Watch":
                try: comp = CompanionProxyService(lockdown).list()
                except: comp = []
            else:
                comp = []
        else:
            pass

    try: 
        if len(udid) > 26:
            udid_s = udid[:25] + "\n" + '{:13}'.format(" ") + "\t" + udid[25:]
        else:
            udid_s = udid
        if len(name) > 26:
            wordnames = name.split()
            if len(' '.join(wordnames[:-1])) < 27:
                name_s = ' '.join(wordnames[:-1]) + "\n" + '{:13}'.format(" ") + "\t" + wordnames[-1]
            else:
                name_s = ' '.join(wordnames[:-2]) + "\n" + '{:13}'.format(" ") + "\t" + ' '.join(wordnames[-2:])
        else:
            name_s = name
        if len(dev_name) > 26:
            wordnames = dev_name.split()
            if len(' '.join(wordnames[:-1])) < 27:
                dev_name_s = ' '.join(wordnames[:-1]) + "\n" + '{:13}'.format(" ") + "\t" + wordnames[-1]
            else:
                dev_name_s = ' '.join(wordnames[:-2]) + "\n" + '{:13}'.format(" ") + "\t" + ' '.join(wordnames[-2:])
        else:
            dev_name_s = dev_name

        if ispaired == True:
            device = ("Device paired ✔ \n\n" +
                '{:13}'.format("Model-Nr: ") + "\t" + dev_name_s +
                "\n" + '{:13}'.format("Dev-Name: ") + "\t" + name_s +
                "\n" + '{:13}'.format("Hardware: ") + "\t" + hardware + ", " + mnr +
                "\n" + '{:13}'.format("Product: ") + "\t" + product +
                "\n" + '{:13}'.format("Software: ") + "\t" + version +
                "\n" + '{:13}'.format("Build-Nr: ") + "\t" + build +
                "\n" + '{:13}'.format("Language: ") + "\t" + language +
                "\n" + '{:13}'.format("Serialnr: ") + "\t" + snr +
                "\n" + '{:13}'.format("MLB-Snr: ") + "\t" + mlbsnr +
                "\n" + '{:13}'.format("Wifi MAC: ") + "\t" + w_mac +
                "\n" + '{:13}'.format("BT MAC: ") + "\t" + b_mac +
                "\n" + '{:13}'.format("Disk Use: ") + "\t" + graph_progress +
                "\n" + '{:13}'.format("Capacity: ") + "\t" + disk + "0 GB" +
                "\n" + '{:13}'.format("Used: ") + "\t" + used + " GB" +
                "\n" + '{:13}'.format("Free: ") + "\t" + free + " GB" +
                "\n" + '{:13}'.format("UDID: ") + "\t" + udid_s +
                "\n" + '{:13}'.format("ECID: ") + "\t" + ecid +
                "\n" + '{:13}'.format("IMEI 1: ") + "\t" + imei +
                "\n" + '{:13}'.format("IMEI 2: ") + "\t" + imei2)
        else:
            device = ("Device unpaired ✗ \n\n" +
            '{:13}'.format("Model-Nr: ") + "\t" + dev_name +
                "\n" + '{:13}'.format("Dev-Name: ") + "\t" + name_s +
                "\n" + '{:13}'.format("Hardware: ") + "\t" + hardware +
                "\n" + '{:13}'.format("Product: ") + "\t" + product +
                "\n" + '{:13}'.format("Software: ") + "\t" + version +
                "\n" + '{:13}'.format("Build-Nr: ") + "\t" + build +
                "\n" + '{:13}'.format("Wifi MAC: ") + "\t" + w_mac +
                "\n" + '{:13}'.format("UDID: ") + "\t" + udid_s +
                "\n" + '{:13}'.format("ECID: ") + "\t" + ecid)  

    except: 
        device = ("No device detected!\n" +
            "\n" + '{:13}'.format("Python: ") + "\t" + platform.python_version() +
            "\n" + '{:13}'.format("PMD3: ") + "\t" + version('pymobiledevice3') +
            "\n" + '{:13}'.format("pyiosbackup: ") + "\t" + version('pyiosbackup') +
            "\n" + '{:13}'.format("iOSbackup: ") + "\t" + version('iOSbackup') +
            "\n" + '{:13}'.format("paramiko: ") + "\t" + version('paramiko') +
            "\n" + '{:13}'.format("pandas: ") + "\t" + version('pandas') +
            "\n\n" + 
            "   59 65 74 20 73 75 63 68 20 69 73 \n" +
            "   20 6F 66 74 20 74 68 65 20 63 6F \n" +
            "   75 72 73 65 20 6F 66 20 64 65 65 \n" +
            "   64 73 20 74 68 61 74 20 6D 6F 76 \n" +
            "   65 20 74 68 65 20 77 68 65 65 6C \n" + 
            "   73 20 6F 66 20 74 68 65 20 77 6F \n" +
            "   72 6C 64 3A 20 73 6D 61 6C 6C 20 \n" + 
            "   68 61 6E 64 73 20 64 6F 20 74 68 \n" +
            "   65 6D 20 62 65 63 61 75 73 65 20 \n" +
            "   74 68 65 79 20 6D 75 73 74 2C 20 \n" +
            "   77 68 69 6C 65 20 74 68 65 20 65 \n" +
            "   79 65 73 20 6F 66 20 74 68 65 20 \n" +
            "   67 72 65 61 74 20 61 72 65 20 65 \n" +
            "   6C 73 65 77 68 65 72 65 2E")

    #Get installed Apps
    if lockdown != None and ispaired != False:
        global apps 
        apps = installation_proxy.InstallationProxyService(lockdown).get_apps("User")
        global app_id_list 
        app_id_list = []
        for app in apps.keys():
            app_id_list.append(app)
        global doc_list
        doc_list = []
        for app in apps:
            try: 
                apps.get(app)['UIFileSharingEnabled']
                doc_list.append("yes")
            except:
                doc_list.append("no")
    else:
        pass
    return(device)

# modified pull function from pymobiledevice3 (sets atime to mtime as it's not readable)
def pull(self, relative_src, dst, fdict=False, callback=None, src_dir=''):
        global filedict
        src = posixpath.join(src_dir, relative_src)
        if callback is not None:
            callback(src, dst)

        src = self.resolve_path(src)

        if not self.isdir(src):
            # normal file
            if "default.realm." in src:
                pass
            else:
                output_format = "%Y-%m-%dT%H:%M:%S-00:00" 
                filecontent = self.get_file_contents(str(src))
                #fdict = True
                if fdict == True:
                    dbfiles = [".db", ".sqlite", ".realm", ".kgdb"]
                    try:                  
                        mimetype = mimetypes.guess_type(src, strict=True)
                        if "image" in mimetype[0]:
                            tag = "Image"
                        elif "video" in mimetype[0]:
                            tag = "Video"
                        elif "audio" in mimetype[0] and not "plj" in mimetype[0]:
                            tag = "Audio"
                        elif "text" in mimetype[0]:
                            tag = "Text"
                        elif "application" in mimetype[0]:
                            tag = "Application"
                        elif any(x in src.lower() for x in dbfiles):
                            tag = "Database"
                        elif any(x in src.lower() for x in dbfiles):
                            tag = "Database"
                        else: 
                            tag = "Uncategorized"
                        #print(src)
                        #print(mimetype)
                        #print(tag)
                    except:
                        mimetype = ["uncategorized", None]
                        if any(x in src.lower() for x in dbfiles):
                            tag = "Database"
                        elif ".plist" in src.lower():
                            tag = "Text"
                        else: 
                            tag = "Uncategorized"
                    finally:
                        filedict[str(src)] = {"size": str(self.stat(src)['st_size']), "accessInfo": {"CreationTime": str(self.stat(src)['st_birthtime'].strftime(output_format)), "ModifyTime": str(self.stat(src)['st_mtime'].strftime(output_format)), "AccessTime": ""}, 
                        "metadata": {"Local Path": os.path.join("files", "AFC", os.path.basename(src)), "SHA256": hashlib.sha256(filecontent).hexdigest(), "MD5": hashlib.md5(filecontent).hexdigest(), "Tags": tag}}
                        if tag == "Image":
                            try:
                                img_bytes = BytesIO()
                                img_bytes.write(filecontent)
                                etags = {}
                                etags = exifread.process_file(img_bytes, details=False)
                                if isinstance(etags, dict):
                                    exifb = True
                                else:
                                    exifb = False
                            except:
                                exifb = False
                            exifdict = {}
                            if exifb == True:
                                try: exifdict['ExifEnumPixelXDimension'] = str(etags['Image XResolution'])
                                except: pass
                                try: exifdict['ExifEnumPixelYDimension'] = str(etags['Image YResolution'])
                                except: pass
                                try: exifdict['ExifEnumOrientation'] = str(etags["Image Orientation"])
                                except: pass
                                try: exifdict['ExifEnumDateTimeOriginal'] = str(etags["EXIF DateTimeOriginal"])
                                except: pass
                                try: exifdict['ExifEnumDateTimeDigitized'] = str(etags["EXIF DateTimeDigitized"])
                                except: pass
                                try: exifdict['ExifEnumMake'] = str(etags["Image Make"])
                                except: pass
                                try: exifdict['ExifEnumModel'] = str(etags["Image Model"])
                                except: pass
                                try: exifdict['ExifEnumExposureTime'] = str(etags["EXIF ExposureTime"])
                                except: pass
                                try: exifdict['ExifEnumFocalLength'] = str(etags["EXIF FocalLength"])
                                except: pass
                                try: exifdict['ExifEnumFNumber'] = str(etags["EXIF FNumber"])
                                except: pass
                                try: exifdict['EXIFCaptureTime'] = str(etags["EXIF CaptureTime"])
                                except: pass
                                try: exifdict['MetaDataPixelResolution'] = f"{str(etags['EXIF ExifImageWidth'])}x{str(etags['EXIF ExifImageLength'])}"
                                except: pass
                                if exifdict != {}:
                                    filedict[str(src)]["Exif"] = exifdict
                                if 'GPS GPSLatitude' in etags.keys():
                                    gpsdict = {}
                                    lat = eval(str(etags['GPS GPSLatitude']))
                                    try: latref = etags['GPS GPSLatitudeRef']
                                    except: latref = "0"
                                    lon = eval(str(etags['GPS GPSLongitude']))
                                    try: lonref = etags['GPS GPSLongitudeRef']
                                    except: lonref = "0"
                                    ele = eval(str(etags['GPS GPSAltitude']))
                                    try: eleref = etags['GPS GPSAltitudeRef']
                                    except: eleref = 0
                                    if eleref == 1:
                                        ele = -ele
                                    ele = int(ele)
                                    deci_lat = lat[0] + lat[1] / 60 + lat[2] / 3600
                                    if latref == "S" or latref =='W' :
                                        deci_lat = -deci_lat
                                    gpsdict['Latitude'] = round(deci_lat, 5)
                                    deci_lon = lon[0] + lon[1] / 60 + lon[2] / 3600
                                    if lonref == "S" or lonref =='W' :
                                        deci_lon = -deci_lon
                                    gpsdict['Longitude'] = round(deci_lon, 5)
                                    gpsdict['Elevation'] = ele
                                    filedict[str(src)]["GPS"] = gpsdict
                            
                mtime = self.stat(src)['st_mtime'].timestamp()
                if os.path.isdir(dst):
                    dst = os.path.join(dst, os.path.basename(relative_src))
                with open(dst, 'wb') as f:
                    f.write(filecontent)
                os.utime(dst, (mtime, mtime))
        else:
            # directory
            dst_path = pathlib.Path(dst) / os.path.basename(relative_src)
            dst_path.mkdir(parents=True, exist_ok=True)

            for filename in self.listdir(src):
                src_filename = posixpath.join(src, filename)
                dst_filename = dst_path / filename

                src_filename = self.resolve_path(src_filename)

                if self.isdir(src_filename):
                    dst_filename.mkdir(exist_ok=True)
                    pull(self, src_filename, str(dst_path), callback=callback, fdict=fdict)
                    continue

                pull(self, src_filename, str(dst_path), callback=callback, fdict=fdict)

# modified unback commanf from pyiosbackup for better Windows support
def unback_alt(self, path='.'):
    dest_dir = pathlib.Path(path)
    dest_dir.mkdir(exist_ok=True, parents=True)
    for file in self.iter_files():
        if platform.uname().system == 'Windows':
                file.relative_path = re.sub(r"[?%*:|\"<>\x7F\x00-\x1F]", "-", file.relative_path)
        dest_file = dest_dir / file.domain / file.relative_path
        dest_file.parent.mkdir(exist_ok=True, parents=True)
        dest_file.write_bytes(file.read_bytes())

def tunnel_win():
    if not verify_tunnel_imports():
        return
    else:
        protocol = TunnelProtocol(TunnelProtocol.QUIC.value)
        TunneldRunner.create(TUNNELD_DEFAULT_ADDRESS[0], TUNNELD_DEFAULT_ADDRESS[1], protocol=protocol)

# Create a temporary script to start the rsd tunnel privileged on linux
def create_linux_shell_script():
    env_vars = os.environ
    script_content = "#!/bin/bash\n"
    
    for key, value in env_vars.items():
        script_content += f'export {key}="{value}"\n'
    
    script_content += f"python3 -m pymobiledevice3 remote tunneld -d\n"
    script_file = tempfile.NamedTemporaryFile(delete=False, suffix=".sh")
    script_file.write(script_content.encode('utf-8'))
    script_file.close()
    os.chmod(script_file.name, 0o755)
    return script_file.name

lockdown = check_device()
try:
    language = lockdown.language
    ispaired = True
except:
    ispaired = False

device = dev_data()
developer = False
filedict = {}


# Start the app
if __name__ == "__main__":
    app = MyApp()
    app.mainloop()

#Restart the app
def restart():
    app.destroy()
    app = MyApp()
    app.mainloop()

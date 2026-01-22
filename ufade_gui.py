#!/usr/bin/env python3
# UFADE - Universal Forensic Apple Device Extractor (c) C.Peter 2024
# Licensed under GPLv3 License
import sys
import os
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")
import customtkinter as ctk
from PIL import ImageTk, Image, ExifTags, ImageDraw, ImageFont
import tkinter.ttk as ttk
from tkinter import StringVar
from tkcalendar import Calendar
from pymobiledevice3 import usbmux, exceptions, lockdown
from pymobiledevice3.services.mobile_image_mounter import DeveloperDiskImageMounter, MobileImageMounterService, PersonalizedImageMounter
from pymobiledevice3.lockdown import create_using_usbmux, create_using_remote
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.companion import CompanionProxyService
from pymobiledevice3.services import installation_proxy
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
from pymobiledevice3.services.springboard import SpringBoardServicesService
from pymobiledevice3.services.afc import AfcService, LockdownService
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
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS, get_tunneld_devices
from pymobiledevice3.tunneld.server import TunneldRunner
from pymobiledevice3.remote.common import TunnelProtocol
from pymobiledevice3.remote.utils import get_rsds
from pymobiledevice3.cli.remote import cli_tunneld
from pymobiledevice3 import irecv
from pymobiledevice3.irecv_devices import IRECV_DEVICES
from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_pem_public_key
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization 
from paramiko import SSHClient, AutoAddPolicy, Transport
from datetime import datetime, timedelta, timezone, date
from concurrent.futures import ThreadPoolExecutor
from subprocess import Popen, PIPE, check_call, run
from pymobiledevice3 import exceptions
from importlib.metadata import version
from iOSbackup import iOSbackup
from ufade import iOSbackupUF
from pyiosbackup import Backup
from io import BytesIO
import simpleaudio as sa
import xml.etree.ElementTree as ET
from xml.dom import minidom
from pdfme import build_pdf
import base64
import mimetypes
import hashlib
import imagehash
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
import time
import tempfile
import re
import exifread
import uuid
import ast
import io

iOSbackup.getFileDecryptedCopy = iOSbackupUF.getFileDecryptedCopy


ctk.set_appearance_mode("dark")  # Dark Mode
ctk.set_default_color_theme("dark-blue") 
ctk.set_window_scaling(1.0)
ctk.set_widget_scaling(1.0) 

class MyApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.stop_event = threading.Event()
        if getattr(sys, 'frozen', False):
            self.report_callback_exception = self.global_exception_handler
            threading.excepthook = lambda args: self.global_exception_handler(args.exc_type, args.exc_value, args.exc_traceback)
            sys.excepthook = lambda exc_type, exc_value, exc_traceback: self.global_exception_handler(exc_type, exc_value, exc_traceback)

        # Define Window
        self.title(f"Universal Forensic Apple Device Extractor {u_version}")
        self.geometry(f"{resx}x{resy}")
        self.resizable(False, False)
        if platform.uname().system == "Darwin":
            self.iconpath = ImageTk.PhotoImage(file=os.path.join(os.path.dirname(__file__), "assets" , "ufade.icns" ))
        else:
            self.iconpath = ImageTk.PhotoImage(file=os.path.join(os.path.dirname(__file__), "assets" , "ufade.png" ))
        self.wm_iconbitmap()
        self.iconphoto(False, self.iconpath)

        # Font:

        ctk.FontManager.load_font(os.path.join(os.path.dirname(__file__), "assets" , "NotoSansMono-UFADE.ttf" ))
        ctk.FontManager.load_font(os.path.join(os.path.dirname(__file__), "assets" , "NotoSans-Medium.ttf" ))
        
        if platform.uname().system == 'Windows':
            self.stfont = ctk.CTkFont("Noto Sans Medium")
            self.monofont = ctk.CTkFont("Noto Sans Mono UFADE")
            self.monofont.configure(size=fsize)
        else:
            self.stfont = ctk.CTkFont("default")
        self.stfont.configure(size=fsize)

        style = ttk.Style()
        style.theme_use("clam")

        # Create frames
        self.left_frame = ctk.CTkFrame(self, width=leftx, corner_radius=0, fg_color="#2c353e", bg_color="#2c353e")
        self.left_frame.grid(row=0, column=0, sticky="ns")

        self.right_frame = ctk.CTkFrame(self, width=rightx, fg_color="#212121")
        self.right_frame.grid(row=0, column=1, sticky="nsew")
        self.grid_columnconfigure(1, weight=1)

        # Widgets (left Frame))
        if platform.uname().system == 'Windows':
            self.info_text = ctk.CTkTextbox(self.left_frame, height=resy, width=leftx, fg_color="#2c353e", corner_radius=0, font=self.monofont, activate_scrollbars=False)
            
        elif platform.uname().system == 'Darwin':
            self.info_text = ctk.CTkTextbox(self.left_frame, height=resy, width=leftx, fg_color="#2c353e", corner_radius=0, font=("Menlo", fsize), activate_scrollbars=False)
        else:
            self.info_text = ctk.CTkTextbox(self.left_frame, height=resy, width=leftx, fg_color="#2c353e", corner_radius=0, font=("monospace", fsize), activate_scrollbars=False)
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
        self.dynamic_frame = ctk.CTkFrame(self.right_frame, corner_radius=0, bg_color="#212121")
        self.dynamic_frame.pack(fill="both", expand=True, padx=0, pady=0)
        self.current_menu = None

        # Show Main Menu
        if lockdown != None:
            if ispaired != False:
                self.show_cwd()
            else:
                self.show_notpaired()
        else:
            if mode == "normal":
                self.show_nodevice()
            else:
                self.show_recovery()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        if hasattr(self, 'linux_17') and self.linux_17:
            try: self.linux_17.kill()
            except: pass
        if hasattr(self, 'mac_os_17') and self.mac_os_17:
            try: self.mac_os_17.kill()
            except: pass
        if hasattr(self, 'tunnel_win') and self.tunnel_win:
            try: self.tunnel_win.kill()
            except: pass            
        self.destroy()
        os._exit(0)

    def show_main_menu(self):
         # Erase content of dynamic frame
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        global lockdown
        try:
            lockdown = create_using_usbmux()
        except:
            self.after(20)
            self.show_nodevice()
            return()
        # Show Main Menu
        self.menu_var.set("MainMenu")
        self.current_menu = "MainMenu"
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Reporting Options", command=lambda: self.switch_menu("iReportMenu"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Acquisition Options", command=lambda: self.switch_menu("AcqMenu"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Logging Options", command=lambda: self.switch_menu("LogMenu"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Developer Options", command=lambda: self.switch_menu("CheckDev"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Advanced Options", command=lambda: self.switch_menu("AdvMenu"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Save informations about the device, installed apps,\nSIM and companion devices.", 
                          "Allows logical, advanced logical and filesystem\nextractions.", 
                          "Collect the AUL, Crash Logs, Sysdiagnose\nand Live Syslogs",
                          "Access developer mode for further options.\nMainly screenshotting options.",
                          "More specific options for data handling."]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

    def switch_menu(self, menu_name, **kwargs):
        # Erase content of dynamic frame
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()

# Switch to chosen menu
        self.current_menu = menu_name
        if menu_name == "AcqMenu":
            self.show_acq_menu()
        if menu_name == "LogMenu":
            self.show_log_menu()
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
        elif menu_name == "iReportMenu":
            self.show_ireport_menu()
        elif menu_name == "PDF":
            self.show_pdf_report()
        elif menu_name == "DevInfo":
            self.show_save_device_info()
        elif menu_name == "iTunes":
            self.show_iTunes_bu()
        elif menu_name == "CustMenue":
            self.show_cust_menu()
        elif menu_name == "advanced":
            self.show_logicalplus(**kwargs)
        elif menu_name == "advanced_cust":
            self.show_advanced_logicalplus()
        elif menu_name == "advanced_cust_ufed":
            self.show_advanced_ufed()
        elif menu_name == "advanced_ufed":
            self.show_ufed(**kwargs)
        elif menu_name == "advanced_cust_prfs":
            self.show_advanced_prfs()            
        elif menu_name == "PRFS":
            self.show_prfs(**kwargs)
        elif menu_name == "ffs_jail":
            self.perf_jailbreak_ssh_dump()
        elif menu_name == "tess":
            self.backup_tess()     
        elif menu_name == "sniff":
            self.show_sniffer()
        elif menu_name == "enc_off":
            self.show_deactivate_encryption()
        elif menu_name == "CollectUL":
            self.show_collect_ul()
        elif menu_name == "LiveSys":
            self.show_capture_syslog()
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
        elif menu_name == "Data":
            self.show_data_menu()

# Watch/TV Menu
    def show_watch_menu(self):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        if d_class == "Watch":
            self.menu_buttons = [
                ctk.CTkButton(self.dynamic_frame, text="Reporting and\nAcquisition Options", command=lambda: self.switch_menu("ReportMenu"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Logging Options", command=lambda: self.switch_menu("LogMenu"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Developer Options", command=lambda: self.switch_menu("CheckDev"), width=200, height=70, font=self.stfont),
                ctk.CTkButton(self.dynamic_frame, text="Extract AFC Media files", command=lambda: self.switch_menu("Media"), width=200, height=70, font=self.stfont),
            ]
            self.menu_text = ["Extract device informations and content.", 
                            "Collect the AUL, Crash Logs, Sysdiagnose\nand Live Syslogs",
                            "Access developer mode for further options.\nMainly screenshotting options.", 
                            "Pull the \"Media\"-folder from the device\n(pictures, videos, recordings)"]
        else:
            self.menu_buttons = [
                ctk.CTkButton(self.dynamic_frame, text="Reporting and\nAcquisition Options", command=lambda: self.switch_menu("ReportMenu"), width=200, height=70, font=self.stfont),
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
        if d_class == "AudioAccessory":
            self.menu_buttons.pop(3)
            self.menu_text.pop(3)
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

# Watch/TV Report Menu
    def show_report_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Save device info", command=lambda: self.switch_menu("DevInfo"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Create PDF Report", command=lambda: self.switch_menu("PDF"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Create UFDR Report", command=lambda: self.switch_menu("Report"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Partially Restored\nFilesystem Backup", command=lambda: self.switch_menu("PRFS"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Save informations about the device, installed apps,\nSIM and companion devices. (as .txt)",
                          "Create a printable PDF device report",
                          "Create a UFDR-Zip container viewable\nin the Cellebrite Reader application",
                          "Try to reconstruct parts of the device-filesystem\nincluding Logs and Media.",]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))
        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_watch_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

#iPhone/iPad Report Menu
    def show_ireport_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Save device info", command=lambda: self.switch_menu("DevInfo"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Create PDF Report", command=lambda: self.switch_menu("PDF"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Save informations about the device, installed apps,\nSIM and companion devices. (as .txt)",
                          "Create a printable PDF device report"]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))
        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

# Acquisition Menu
    def show_acq_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Logical Backup", command=lambda: self.switch_menu("iTunes"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Logical+ Backup\n(UFED-Style)", command=lambda: self.switch_menu("advanced_ufed"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Partially Restored\nFilesystem Backup", command=lambda: self.switch_menu("PRFS"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Filesystem Backup\n(jailbroken)", command=lambda: self.switch_menu("ffs_jail"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Customize Backup", fg_color="#2d2d35", command=lambda: self.switch_menu("CustMenue"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Perform a backup as iTunes would do it.", 
                          "Creates an advanced Logical Backup as ZIP\nwith an UFD File for PA.",
                          "Try to reconstruct parts of the device-filesystem\nincluding a decrypted Backup, Logs and Media.",
                          "Creates a FFS Backup of an already\njailbroken Device",
                          "Create backups and decide what\ncontent to include."]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

# Individual Acquisition Menu
    def show_cust_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Logical+ Backup", command=lambda: self.switch_menu("advanced_cust"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Logical+ Backup\n(UFED-Style)", command=lambda: self.switch_menu("advanced_cust_ufed"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Partially Restored\nFilesystem Backup", command=lambda: self.switch_menu("advanced_cust_prfs"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Perform and decrypt an iTunes backup,\ngather AFC-media files, shared App\nfolders and crash reports.", 
                          "Creates an advanced Logical Backup as ZIP\nwith an UFD File for PA.",
                          "Try to reconstruct parts of the device-filesystem\nincluding a decrypted Backup, Logs and Media."]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=lambda: self.switch_menu("AcqMenu")).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

# Advanced Backup Option Menues

    def show_advanced_logicalplus(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Customize Logical+ Backup", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Select the content to be created and retained:", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=15)
        self.incl_media = ctk.StringVar(value="on")
        self.incl_media_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include AFC-Media Files.", variable=self.incl_media, onvalue="on", offvalue="off")
        self.incl_media_box.pack(anchor="w", padx= 80, pady=5)
        self.incl_apps = ctk.StringVar(value="on")
        self.incl_apps_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include shared App Files.", variable=self.incl_apps, onvalue="on", offvalue="off")
        self.incl_apps_box.pack(anchor="w", padx= 80, pady=5)
        self.incl_crash = ctk.StringVar(value="on")
        self.incl_crash_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include Crash-Logs.", variable=self.incl_crash, onvalue="on", offvalue="off")
        self.incl_crash_box.pack(anchor="w", padx= 80, pady=5)
        self.keep_bu = ctk.StringVar(value="off")
        self.keep_bu_box = ctk.CTkCheckBox(self.dynamic_frame, text="Don't delete the iTunes Backup Folder.", variable=self.keep_bu, onvalue="on", offvalue="off")
        self.keep_bu_box.pack(anchor="w", padx=80, pady=5)
        self.incl_ul = ctk.StringVar(value="off")
        self.incl_ul = ctk.CTkCheckBox(self.dynamic_frame, text="Additionally extract Unified Logs.", variable=self.incl_ul, onvalue="on", offvalue="off")
        self.incl_ul.pack(anchor="w", padx= 80, pady=5)
        self.startb = ctk.CTkButton(self.dynamic_frame, text="Start", font=self.stfont, command=lambda: self.switch_menu("advanced", incl_ul=self.incl_ul.get(), keep_bu=self.keep_bu.get(), incl_crash=self.incl_crash.get(), incl_media=self.incl_media.get(), incl_apps=self.incl_apps.get(), keep_ul="on"))
        self.startb.pack(pady=20) 
        self.backb = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, fg_color="#8c2c27", command=lambda: self.switch_menu("CustMenue"))
        self.backb.pack(pady=5)

    def show_advanced_ufed(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Customize Logical+ Backup (UFED-Style)", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Select the content to be created and retained:", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=15)
        self.incl_crash = ctk.StringVar(value="off")
        self.incl_media = ctk.StringVar(value="on")
        self.incl_media_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include AFC-Media Files.", variable=self.incl_media, onvalue="on", offvalue="off")
        self.incl_media_box.pack(anchor="w", padx= 80, pady=5)
        self.incl_apps = ctk.StringVar(value="on")
        self.incl_apps_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include shared App Files.", variable=self.incl_apps, onvalue="on", offvalue="off")
        self.incl_apps_box.pack(anchor="w", padx= 80, pady=5)
        self.keep_bu = ctk.StringVar(value="off")
        self.keep_bu_box = ctk.CTkCheckBox(self.dynamic_frame, text="Don't delete the iTunes Backup Folder.", variable=self.keep_bu, onvalue="on", offvalue="off")
        self.keep_bu_box.pack(anchor="w", padx=80, pady=5)
        self.incl_ul = ctk.StringVar(value="off")
        self.incl_ul = ctk.CTkCheckBox(self.dynamic_frame, text="Additionally extract Unified Logs.", variable=self.incl_ul, onvalue="on", offvalue="off")
        self.incl_ul.pack(anchor="w", padx= 80, pady=5)
        self.startb = ctk.CTkButton(self.dynamic_frame, text="Start", font=self.stfont, command=lambda: self.switch_menu("advanced_ufed", incl_ul=self.incl_ul.get(), keep_bu=self.keep_bu.get(), incl_crash=self.incl_crash.get(), incl_media=self.incl_media.get(), incl_apps=self.incl_apps.get(), keep_ul="on"))
        self.startb.pack(pady=20) 
        self.backb = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, fg_color="#8c2c27", command=lambda: self.switch_menu("CustMenue"))
        self.backb.pack(pady=5)

    def show_advanced_prfs(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Customize PRFS Backup", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Select the content to be created and retained:", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=15)
        self.incl_media = ctk.StringVar(value="on")
        self.incl_media_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include AFC-Media Files.", variable=self.incl_media, onvalue="on", offvalue="off")
        self.incl_media_box.pack(anchor="w", padx= 80, pady=5)
        self.incl_apps = ctk.StringVar(value="on")
        self.incl_apps_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include shared App Files.", variable=self.incl_apps, onvalue="on", offvalue="off")
        self.incl_apps_box.pack(anchor="w", padx= 80, pady=5)
        self.incl_crash = ctk.StringVar(value="on")
        self.incl_crash_box = ctk.CTkCheckBox(self.dynamic_frame, text="Include Crash-Logs.", variable=self.incl_crash, onvalue="on", offvalue="off")
        self.incl_crash_box.pack(anchor="w", padx= 80, pady=5)
        self.keep_bu = ctk.StringVar(value="off")
        self.keep_bu_box = ctk.CTkCheckBox(self.dynamic_frame, text="Don't delete the iTunes Backup Folder.", variable=self.keep_bu, onvalue="on", offvalue="off")
        self.keep_bu_box.pack(anchor="w", padx=80, pady=5)
        self.incl_ul = ctk.StringVar(value="on")
        self.incl_ul = ctk.CTkCheckBox(self.dynamic_frame, text="Include Unified Logs.", variable=self.incl_ul, onvalue="on", offvalue="off")
        self.incl_ul.pack(anchor="w", padx= 80, pady=5)
        self.keep_ul = ctk.StringVar(value="off")
        self.keep_ul = ctk.CTkCheckBox(self.dynamic_frame, text="Don't delete the Unified Logs Folder.", variable=self.keep_ul, onvalue="on", offvalue="off")
        self.keep_ul.pack(anchor="w", padx= 80, pady=5)
        self.startb = ctk.CTkButton(self.dynamic_frame, text="Start", font=self.stfont, command=lambda: self.switch_menu("PRFS", incl_ul=self.incl_ul.get(), keep_bu=self.keep_bu.get(), incl_crash=self.incl_crash.get(), incl_media=self.incl_media.get(), incl_apps=self.incl_apps.get(), keep_ul=self.keep_ul.get()))
        self.startb.pack(pady=20) 
        self.backb = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, fg_color="#8c2c27", command=lambda: self.switch_menu("CustMenue"))
        self.backb.pack(pady=5)


# Logging Options Menu
    def show_log_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Collect Unified Logs", command=lambda: self.switch_menu("CollectUL"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Extract crash reports", command=lambda: self.switch_menu("CrashReport"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Initiate Sysdiagnose", command=lambda: self.switch_menu("SysDiag"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Capture Live Syslogs", command=lambda: self.switch_menu("LiveSys"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Collects the AUL from the device and saves\nthem as a logarchive.", 
                          "Pull the crash report folder from the device.", 
                          "Create a Sysdiagnose archive on the device and\npull it to the disk afterwards.",
                          "Capture the Live Syslogs from the device and\nwrite them to a textfile."]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        if d_class == "Watch":
            ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_watch_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )
        else:
            ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )


# Developer Options Menu
    def show_dev_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Take screenshots", command=lambda: self.switch_menu("Shot"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Chat capture", command=lambda: self.switch_menu("ChatLoop"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Capture filesystem\nto text", command=lambda: self.switch_menu("FileLS"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Unmount\nDeveloperDiskImage", command=lambda: self.switch_menu("umount"), width=200, height=70, font=self.stfont),
        ]
        self.menu_text = ["Take screenshots from device screen.\nScreenshots will be saved under \"screenshots\"\nas PNG.", 
                          "Loop through a chat taking screenshots.\nOne screenshot is taken per message.", 
                          "Write a filesystem list to a textfile. (iOS < 16)\nStarting from /var Folder.\nThis may take some time.",
                          "Try to unmount the image.\nReboot the device if this fails"]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=70, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        if d_class == "Watch":
            ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_watch_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )
        else:
            ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

# Advanced Options Menu
    def show_adv_menu(self):
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="WhatsApp export\n(PuMA)", command=lambda: self.switch_menu("tess"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Sniff device traffic", command=lambda: self.switch_menu("sniff"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Extract AFC Media files", command=lambda: self.switch_menu("Media"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Remove UFADE Backup\nPassword", command=lambda: self.switch_menu("enc_off"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Switch to\nFile Operations", fg_color="#2d2d35", command=lambda: self.switch_menu("Data"), width=200, height=70, font=self.stfont)
        ]
        self.menu_text = ["Perform an iTunes-style backup and extract\nWhatsapp files for PuMA (LE-tool).", 
                          "Captures the device network traffic as a pcap file.",
                          "Pull the \"Media\"-folder from the device\n(pictures, videos, recordings)",
                          "Try to remove the encryption password\nset by UFADE",
                          "Show options for operations with\nexisting backups."
                          ]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=50, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        ctk.CTkButton(self.dynamic_frame, text="Back", command=self.show_main_menu).grid(row=r, column=1, padx=10, pady=10, sticky="e" )

# Data Options Menu
    def show_data_menu(self):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        self.skip = ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
        self.skip.grid(row=0, column=0, columnspan=2, sticky="w")
        self.menu_buttons = [
            ctk.CTkButton(self.dynamic_frame, text="Decrypt Backup", command=lambda: self.show_unback("decrypt"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Decrypt and Unback\nBackup", command=lambda: self.show_unback("unback"), width=200, height=70, font=self.stfont),
            ctk.CTkButton(self.dynamic_frame, text="Switch to\nLive Operations", fg_color="#2d2d35", command=self.show_nodevice, width=200, height=70, font=self.stfont)
        ]
        self.menu_text = ["Decrypt an iTunes Backup and keep the\nBackup Structure. ",
                          "Decrypt an iTunes Backup and try to restore\nthe original Filesystem Structure. ", 
                          "Restart UFADE to work with a Device."
                          ]
        self.menu_textbox = []
        for btn in self.menu_buttons:
            self.menu_textbox.append(ctk.CTkLabel(self.dynamic_frame, width=right_content, height=50, font=self.stfont, anchor="w", justify="left"))

        r=1
        i=0
        for btn in self.menu_buttons:
            btn.grid(row=r,column=0, padx=30, pady=10)
            self.menu_textbox[i].grid(row=r,column=1, padx=10, pady=10)
            self.menu_textbox[i].configure(text=self.menu_text[i])
            r+=1
            i+=1

        device = ("\n   These options are intended\n" +
                  "   for encrypted backups with\n" + 
                  "   a known backup password." + "\n\n" +
                  "   The following modules are\n" + 
                  "   used for decryption:" + "\n" +
                "\n   " + '{:13}'.format("pyiosbackup: ") + "\t" + version('pyiosbackup') +
                "\n   " + '{:13}'.format("pandas: ") + "\t" + version('pandas') +
                "\n\n" + 
                "   41 6E 64 20 77 65 20 73 68 6F 75 \n" +
                "   6C 64 6E 27 74 20 62 65 20 68 65 \n" +
                "   72 65 20 61 74 20 61 6C 6C 2C 20 \n" +
                "   69 66 20 77 65 27 64 20 6B 6E 6F \n" +
                "   77 6E 20 6D 6F 72 65 20 61 62 6F \n" +
                "   75 74 20 69 74 20 62 65 66 6F 72 \n" +
                "   65 20 77 65 20 73 74 61 72 74 65 \n" +
                "   64 2E")

        self.info_text.configure(state="normal")
        self.info_text.delete("0.0", "end")
        self.info_text.configure(text_color="#4d5760")
        self.info_text.insert("0.0", device)
        self.info_text.configure(state="disabled")


# device is in recovery or dfu mode:
    def show_recovery(self):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        self.after(10)
        global mode
        device = dev_data()
        self.info_text.configure(state="normal")
        self.info_text.delete("0.0", "end")
        self.info_text.configure(text_color="#abb3bd")
        self.info_text.insert("0.0", device)
        self.info_text.configure(state="disabled")

        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="center")
        self.text = ctk.CTkLabel(self.dynamic_frame, width=400, height=180, font=self.stfont, anchor="w", justify="left")
        self.text.configure(text="A device found in " + mode + " mode.\n\n" +
                            "You can try to reboot the device to a working state.\nWait some time before trying to reconnect.\n" + 
                            "Devices in DFU mode might need a hard-reset.")
        self.text.pack(pady=50)
        ctk.CTkButton(self.dynamic_frame, text="Reboot", command=self.reboot_button).pack(pady=10)
        ctk.CTkButton(self.dynamic_frame, text="Exit Recovery Mode", command=self.exit_loop_button).pack(pady=10)


# reboot button function:
    def reboot_button(self):
        irecv.IRecv(timeout=0.1).reboot()
        global device
        device = dev_data()
        self.show_nodevice()

# exit loop button function:
    def exit_loop_button(self):
        irecv.IRecv(timeout=0.1).set_autoboot(True)
        irecv.IRecv(timeout=0.1).reboot()
        global device
        device = dev_data()
        self.show_nodevice()

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
            ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="center")
            self.text = ctk.CTkLabel(self.dynamic_frame, width=400, height=250, font=self.stfont, anchor="w", justify="left")
            self.text.configure(text="No device found!\n\n" +
                            "Make sure the device is connected and confirm \nthe \"trust\" message on the device screen.\n\n" +
                            "On a Windows-system, make sure \"Apple Devices\" \nor \"iTunes\" is installed.")
            self.text.pack(pady=50)
            ctk.CTkButton(self.dynamic_frame, text="Check again", command=self.show_nodevice).pack(pady=10)
            ctk.CTkButton(self.dynamic_frame, text="Data Operations", fg_color="#2d2d35", command=lambda: self.show_cwd(data=True)).pack(pady=10)
            device = nodevice_text
            self.info_text.configure(state="normal")
            self.info_text.delete("0.0", "end")
            self.info_text.configure(text_color="#4d5760")
            self.info_text.insert("0.0", device)
            self.info_text.configure(state="disabled")
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
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="center")
        self.text = ctk.CTkLabel(self.dynamic_frame, width=400, height=250, font=self.stfont, anchor="w", justify="left")
        self.text.configure(text="Device not paired!\n\n" +
                          "Make sure the device is connected and confirm \nthe \"trust\" message on the device screen.\n\n" +
                          "Provide a supervision profile if needed.")
        self.text.pack(pady=30)
        global lockdown
        global ispaired
        try:
            language = lockdown.language
            ispaired = True
        except:
            ispaired = False
        if ispaired == False:
            ctk.CTkButton(self.dynamic_frame, text="Pair", command=self.pair_button).pack(pady=10)
            ctk.CTkButton(self.dynamic_frame, text="Pair Supervised", fg_color="#2d2d35", command=self.show_supervised).pack(pady=10)
        else:
            lockdown = check_device()
            device = dev_data()
            self.info_text.configure(state="normal")
            self.info_text.delete("0.0", "end")
            self.info_text.configure(text_color="#abb3bd")
            self.info_text.insert("0.0", device)
            self.info_text.configure(state="disabled")
            self.show_cwd()
            
# A device is connected but supervised
    def show_supervised(self):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        self.after(10)
        global lockdown
        global ispaired
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="center")
        self.text = ctk.CTkLabel(self.dynamic_frame, width=400, height=40, font=self.stfont, anchor="w", justify="left")
        self.text.configure(text="\n\n\n\n\n\nProvide the supervision certificate (P12/PKCS12) and the password.")
        self.text.pack(pady=10)

        self.browsebutton = ctk.CTkButton(self.dynamic_frame, text="Browse", font=self.stfont, command=lambda: self.browse_p12(self.p12box), width=40, fg_color="#2d2d35")
        self.browsebutton.pack(side="bottom", pady=(0,410), padx=(0,sb_button_offset_x))
        self.p12box = ctk.CTkEntry(self.dynamic_frame, width=340, height=20, corner_radius=0, placeholder_text=".p12 file")
        self.p12box.bind(sequence="<Return>", command=lambda x: self.pair_supervised(self.text, self.p12box.get(), self.p12passbox.get()))
        #self.p12box.insert(0, string=dir)
        self.p12box.pack(side="left", pady=(90,0), padx=(75,0))  
        self.p12passbox = ctk.CTkEntry(self.dynamic_frame, width=120, height=20, corner_radius=0, placeholder_text="Password",show="*")
        self.p12passbox.bind(sequence="<Return>", command=lambda x: self.pair_supervised(self.text, self.p12box.get(), self.p12passbox.get()))
        #self.p12box.insert(0, string=dir)
        self.p12passbox.pack(side="left", pady=(90,0), padx=(10,0)) 
        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.pair_supervised(self.text, self.p12box.get(), self.p12passbox.get()))
        self.okbutton.pack(side="left", pady=(90,0), padx=(10,120))

# Pair the supervised device
    def pair_supervised(self, text, p12_file, password):
        text.configure(text="\n\n\n\n\nChecking certificate and password.\nThis may take some time.")
        text.update()
        self.after(10)
        global ispaired
        global lockdown
        self.browsebutton.pack_forget()
        self.p12box.pack_forget()
        self.p12passbox.pack_forget()
        self.okbutton.pack_forget()
        self.after(100)
        if pathlib.Path(p12_file).is_file():
            cert = keybag_from_p12(p12_file, password)
            if cert != "error":
                ispaired = False
                while ispaired == False:
                    try: 
                        lockdown.pair_supervised(cert)
                        ispaired = True
                    except:
                        pass
   
                self.show_nodevice()
            else:
                text.configure(text="\n\n\n\n\n\nError loading certificate. Wrong password?")
                ctk.CTkButton(self.dynamic_frame, text="OK", command=self.show_nodevice).pack(pady=50)
        else:
            text.configure(text="\n\n\n\n\n\nNo file selected!")
            ctk.CTkButton(self.dynamic_frame, text="OK", command=self.show_nodevice).pack(pady=50)

# Select the working directory
    def show_cwd(self, data=False):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        global dir
        if getattr(sys, 'frozen', False):
            dir = os.path.join(os.path.expanduser('~'), "ufade_out")
        else:
            dir = os.getcwd()
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="center")
        ctk.CTkLabel(self.dynamic_frame, text="Choose Output Directory:", height=30, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.browsebutton = ctk.CTkButton(self.dynamic_frame, text="Browse", font=self.stfont, command=lambda: self.browse_cwd(self.outputbox), width=60, fg_color="#2d2d35")
        self.browsebutton.pack(side="bottom", pady=(0,b_button_offset_y), padx=(0,b_button_offset_x))
        self.outputbox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text=[dir])
        self.outputbox.bind(sequence="<Return>", command=lambda x: self.choose_cwd(self.outputbox))
        self.outputbox.insert(0, string=dir)
        self.outputbox.pack(side="left", pady=(110,0), padx=(130,0))  
        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.choose_cwd(self.outputbox, data))
        self.okbutton.pack(side="left", pady=(110,0), padx=(10,120))
        
# Function to choose the working directoy
    def choose_cwd(self, outputbox, data=False):
        global dir
        global dir_top
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
        if len(dir) > 48:
            dir_top = f"{dir[:45]}..."
        else:
            dir_top = dir
        if data == False:
            if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
                self.show_watch_menu()
            else:
                self.show_main_menu()
        else:
            self.show_data_menu()

# Filebrowser for working direcory
    def browse_cwd(self, outputbox):
        global dir
        olddir = dir
        self.okbutton.configure(state="disabled")
        outputbox.configure(state="disabled")
        if platform.uname().system == 'Linux':
            try:
                import crossfiledialog
                dir = crossfiledialog.choose_folder()
                if dir == "":
                    dir = olddir
            except:
                dir = ctk.filedialog.askdirectory()
                if not dir:
                    dir = olddir
        else:
            dir = ctk.filedialog.askdirectory()
            if not dir:
                dir = olddir
        self.okbutton.configure(state="enabled")
        outputbox.configure(state="normal")    
        outputbox.delete(0, "end")
        outputbox.insert(0, string=dir)

# Filebrowser for p12 file
    def browse_p12(self, p12box):
        global p12_file
        self.okbutton.configure(state="disabled")
        p12box.configure(state="disabled")
        if platform.uname().system == 'Linux':
            import crossfiledialog
            p12_file = crossfiledialog.open_file(filter="*.p12")
        else:
            p12_file = ctk.filedialog.askopenfilename(filetypes=[("PKCS12 files", ".p12")])
        self.okbutton.configure(state="enabled")
        p12box.configure(state="normal")    
        p12box.delete(0, "end")
        if p12_file != "":
            p12box.insert(0, string=p12_file)
        else:
            p12box.configure(placeholder_text=".p12 file")
        
# Save device info to file and show the available content
    def show_save_device_info(self):
        save_info()
        text = "Device info saved to: \ndevice_" + udid + ".txt\n\nContains:\n- device information\n"
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        if number != "":
            text = text + "- phone number\n"
        if comp != []:
            text = text + "- companion udid\n"
        if all != "" and all != None and all != []:
            text = text + "- SIM information\n"
        if app_id_list != []:
            text = text + "- app information"
        self.text = ctk.CTkLabel(self.dynamic_frame, width=420, height=200, font=self.stfont, text=text, anchor="w", justify="left")
        self.text.pack(pady=50)
        if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
            ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_watch_menu).pack(pady=10)
        else:
            ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=10)

# Try to deactivate the UFADE encryption password
    def show_deactivate_encryption(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Deactivate Encryption Password", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Trying to deactivate the encryption password.\nProvide PIN/Password if prompted.", width=585, height=60, font=self.stfont, anchor="w", justify="left")   
        self.text.pack(pady=25)
        self.change = ctk.IntVar(self, 0)
        remove_enc = threading.Thread(target=lambda: self.deactivate_encryption(change=self.change))
        remove_enc.start()
        self.wait_variable(self.change)
        if self.change.get() == 1:
            self.text.configure(text="Password removed.")
        else:
            self.text.configure(text="Something went wrong. Try again.")
        ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AdvMenu")).pack(pady=10)

# Unified Logs Collecting screen
    def show_collect_ul(self):
        save_info()
        time = None
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Collect Unified Logs", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Collecting Unified Logs will take some time.\ndo you want to continue?", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=25)
        self.choose = ctk.BooleanVar(self, False)
        self.logtime = ctk.BooleanVar(self, False)
        self.yesb = ctk.CTkButton(self.dynamic_frame, text="YES", font=self.stfont, command=lambda: self.choose.set(True))
        self.yesb.pack(side="left", pady=(0,350), padx=(120,30))
        self.timeb = ctk.CTkButton(self.dynamic_frame, fg_color="#2d2d35", text="Select start time ", font=self.stfont, command=lambda: [self.logtime.set(True), self.choose.set(True)])
        self.timeb.pack(side="left", pady=(0,350), padx=(0,30))
        self.nob = ctk.CTkButton(self.dynamic_frame, text="NO", font=self.stfont, command=lambda: self.choose.set(False))
        self.nob.pack(side="left", pady=(0,350))    
        self.wait_variable(self.choose)                             
        if self.choose.get() == True:  
            self.yesb.pack_forget()
            self.timeb.pack_forget()
            self.nob.pack_forget()
            if self.logtime.get() == True:
                self.choose.set(False)
                self.text.configure(text="Select a start time:", height=10, width=300)
                self.logcal = Calendar(
                    master= self.dynamic_frame,
                    font=(ctk.CTkFont("default"),12),
                    locale="en_US",
                    date_pattern="dd.mm.yy", 
                    background="#2b2b2b",    
                    foreground="#dce4ee",       
                    selectbackground="#1f538d",  
                    selectforeground="#dce4ee",   
                    headersbackground="#333333", 
                    headersforeground="#dce4ee",
                    bordercolor="#212121",
                    normalbackground="#2b2b2b",
                    normalforeground="#dce4ee",
                    weekendbackground="#2b2b2b",
                    weekendforeground="#aaaaaa",
                    othermonthbackground="#212121",
                    othermonthforeground="#555555",
                    othermonthwebackground="#212121",
                    othermonthweforeground="#555555"
                )
                self.logcal.pack()
                self.yesb = ctk.CTkButton(self.dynamic_frame, text="Select", font=self.stfont, command=lambda: self.choose.set(True))
                self.yesb.pack(side="left", pady=(30,350), padx=150)
                self.nob = ctk.CTkButton(self.dynamic_frame, text="Cancel", font=self.stfont, command=lambda: self.choose.set(False))
                self.nob.pack(side="left", pady=(30,350))
                self.wait_variable(self.choose)
                self.yesb.pack_forget()
                self.nob.pack_forget()
                self.logcal.pack_forget()
                if self.choose.get() == True:                             
                    start = self.logcal.get_date()
                    sdate = datetime.strptime(start, "%d.%m.%y")
                    time = int(datetime.timestamp(sdate))
                else:
                    if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
                        self.show_watch_menu()
                        return()
                    else:
                        self.switch_menu("LogMenu")
                        return()
    
            self.text.configure(text="Collecting Unified Logs from device.\nThis may take some time.", height=60, width=585)
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
            self.progress.pack()
            self.progress.start()
            self.waitul = ctk.IntVar(self, 0)
            self.coll = threading.Thread(target=lambda: self.collect_ul(time=time, text=self.text, waitul=self.waitul))
            self.coll.start()
            self.wait_variable(self.waitul)
            self.progress.stop()
            self.progress.pack_forget()
            if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_watch_menu).pack(pady=10)
            else:
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("LogMenu")).pack(pady=10)
        else:
            if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
                self.show_watch_menu()
            else:
                self.switch_menu("LogMenu")

# Live Syslog screen
    def show_capture_syslog(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Capture Live Syslogs", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Press “Start” to begin recording the syslogs.\n“Stop” pauses the recording.", width=585, height=70, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=25)
        self.sysl = threading.Thread(target=lambda: self.capture_syslog(text=self.text, startb=self.startb, backb=self.backb))
        self.startb = ctk.CTkButton(self.dynamic_frame, text="Start", font=self.stfont, command=lambda: self.sysl.start())
        self.startb.pack(pady=20) 
        if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
            self.backb = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, command=self.show_watch_menu)
            self.backb.pack(pady=10)
        else:
            self.backb = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, command=lambda: self.switch_menu("LogMenu"))
            self.backb.pack(pady=10)


# Crash Report extraction as single function or as part of a flow
    def show_crash_report(self, cdir="Crash_Report", flow=False):
        save_info()
        if flow == False:
            cdir = f'Crash_Logs_{udid}_{str(datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))}'
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Extract Crash Reports", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Extracting crash reports from device.\nThis may take some time.", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(pady=25)
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.progress.pack()
        self.change = ctk.IntVar(self, 0)
        if flow != False:
            self.crash = threading.Thread(target=lambda: crash_report(crash_dir=cdir, change=self.change, progress=self.progress, prog_text=self.prog_text))
        else:
            self.crash = threading.Thread(target=lambda: crash_report(crash_dir=cdir, change=self.change, progress=self.progress, prog_text=self.prog_text, czip=True))
        self.crash.start()
        self.wait_variable(self.change)
        self.progress.stop()
        self.progress.pack_forget()
        self.prog_text.pack_forget()
        if flow == False:
            self.text.configure(text="Extraction of crash reports completed!")
            if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_watch_menu).pack(pady=10)
            else:
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("LogMenu")).pack(pady=10)
        else:
            pass

    def show_sysdiag(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Extract Sysdiagnose", height=60, width=585, font=("standard",24), justify="left").pack(pady=15)
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
            elif d_class == "AppleTV":
                self.text.configure(text="To trigger the creation of the Sysdiagnose files,\npress: Play/Pause + Volume Down for 6 seconds on the remote.")
            else:
                self.text.configure(text="To trigger the creation of the Sysdiagnose files,\npress: Power/Side + VolUp + VolDown for 0.215 seconds.")
            self.text.pack()
            if d_class == "Watch":
                self.diag_image = ctk.CTkImage(dark_image=Image.open(os.path.join(os.path.dirname(__file__), "assets" , "diag_watch.png")), size=(600, 300))
            elif d_class == "iPad":
                self.diag_image = ctk.CTkImage(dark_image=Image.open(os.path.join(os.path.dirname(__file__), "assets" , "diag_ipad.png")), size=(600, 300))
            elif d_class == "AppleTV":
                self.diag_image = ctk.CTkImage(dark_image=Image.open(os.path.join(os.path.dirname(__file__), "assets" , "diag_tv.png")), size=(600, 300))
            else:
                self.diag_image = ctk.CTkImage(dark_image=Image.open(os.path.join(os.path.dirname(__file__), "assets" , "diag.png")), size=(600, 300))
            self.diaglabel = ctk.CTkLabel(self.dynamic_frame, image=self.diag_image, text=" ", width=600, height=300, font=self.stfont, anchor="w", justify="left")
            self.diaglabel.pack()
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
            self.waitsys = ctk.IntVar(self, 0)
            self.diag = threading.Thread(target=lambda: self.sysdiag(self.text, self.progress, self.waitsys))
            self.diag.start()
            self.wait_variable(self.waitsys)
            if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_watch_menu).pack(pady=10)
            else:
                ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("LogMenu")).pack(pady=10)     
        else:
            if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
                self.show_watch_menu()
            else:
                self.switch_menu("LogMenu")

# Sysdiagnose creation screen
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
            text.pack(pady=30)
            progress.pack()
            progress.start()
            self.diagsrv._wait_for_sysdiagnose_to_finish()
            text.configure(text="Pulling the Sysdiagnose archive from the device")
            self.diagsrv.pull(out=f"{udid}_sysdiagnose.tar.gz", entry=sysdiagname,erase=True)
            text.configure(text="Extraction of Sysdiagnose archive completed!")
            log("Extracted Sysdiagnose file")
            progress.pack_forget()
        except:
            text.configure(text="Extraction of Sysdiagnose canceled!")
            log("Sysdiagnose extraction canceled")
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

    def pair_super_button(self):
        self.paired = ctk.BooleanVar(self, False)
        self.pair = threading.Thread(target=lambda: pair_supervised_device(paired=self.paired))
        self.pair.start()
        self.wait_variable(self.paired)
        self.show_notpaired()

# Play a notification sound
    def notification(self):
        try:      
            sa.WaveObject.from_wave_file(os.path.join(os.path.dirname(__file__), "assets", "notification.wav")).play()
        except Exception as e:
            log(f"Error playing notification: {e}")

# Unified logs collection function
    def collect_ul(self, time, text, waitul, mode="default"):
        if mode == "default":
            try: os.mkdir("unified_logs")
            except: pass
        uname = f'{udid}_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}.logarchive'
        try:
            if mode == "default":
                OsTraceService(lockdown).collect(out= os.path.join("unified_logs", uname), start_time=time)
                text.configure(text=f"Unified Logs written to:\n{uname}")
                log(f"Collected Unified Logs as {uname}")
            else:
                OsTraceService(lockdown).collect(out=f"{udid}.logarchive", start_time=time) 
                log(f"Collected Unified Logs with a Backup.")
            waitul.set(1)  
        except:
            text.configure(text="Error: \nCould not collect logs - Maybe the device or its iOS version is too old.")
            log("Error collecting Unified Logs")
            waitul.set(2)
        try: os.rmdir("unified_logs")
        except: pass

# Include Unified Logs in PRFS-Zip-archive 
    def zip_ul(self, zip, text, waitul):
        source_folder = f"{udid}.logarchive"
        MIN_TS = time.mktime((1980, 1, 1, 0, 0, 0, 0, 1, -1))
        hex_pattern = re.compile(r'^[0-9A-Fa-f]{2}$')
        try:
            with open(os.path.join(source_folder, "Info.plist"), mode='rb') as infofile:
                readinfo = plistlib.load(infofile)
            ver_file = readinfo.get("SpecialMetadata", "")["TTL"]
            ver_file["Version"] = 7
            ver_file["Identifier"] = readinfo.get("SourceIdentifier", "")
            verfile = os.path.join(source_folder, "version.plist")
            with open(verfile, "wb") as file:
                plistlib.dump(ver_file, file, fmt=plistlib.FMT_BINARY)
            zip.write(verfile, "private/var/db/diagnostics/version.plist")

            for item in os.listdir(source_folder):
                item_path = os.path.join(source_folder, item)
                
                if os.path.isdir(item_path):
                    if item == "Extra":
                        for root, dirs, files in os.walk(item_path):
                            rel_root = os.path.relpath(root, item_path)
                            archive_root = posixpath.join("private/var/db/diagnostics", rel_root) if rel_root != "." else "private/var/db/diagnostics"
                            if not files and not dirs:
                                zipinfo = zipfile.ZipInfo(archive_root + '/')
                                zip.writestr(zipinfo, '')
                            for file in files:
                                if "._" not in file:
                                    file_path = os.path.join(root, file)
                                    stat = os.stat(file_path)
                                    if stat.st_mtime < MIN_TS:
                                        os.utime(file_path, (stat.st_atime, MIN_TS))
                                    archive_name = posixpath.join(archive_root, file)
                                    zip.write(file_path, archive_name)
                                else:
                                    pass
                        continue 

                    if item == "dsc" or hex_pattern.fullmatch(item):
                        target_path = posixpath.join("private/var/db/uuidtext", item)
                    else:
                        target_path = posixpath.join("private/var/db/diagnostics", item)

                    for root, dirs, files in os.walk(item_path):
                        rel_root = os.path.relpath(root, item_path)
                        archive_root = posixpath.join(target_path, rel_root) if rel_root != "." else target_path
                        if not files and not dirs:
                            zipinfo = zipfile.ZipInfo(archive_root + '/')
                            zip.writestr(zipinfo, '')
                        for file in files:
                            if "._" not in file:
                                file_path = os.path.join(root, file)
                                stat = os.stat(file_path)
                                if stat.st_mtime < MIN_TS:
                                    os.utime(file_path, (stat.st_atime, MIN_TS))
                                archive_name = posixpath.join(archive_root, file)
                                zip.write(file_path, archive_name)
                            else:
                                pass
        except Exception as e:
            print(e)
            pass
        waitul.set(1)
       



# Live Syslog function
    def capture_syslog(self, text, startb, backb):
        fname = f'{udid}_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}_livelog.txt'
        sysloglive = OsTraceService(lockdown)
        #text.configure(height=200, wraplength=900, anchor="nw")
        startb.configure(text="Stop", command=lambda: sysloglive.close())
        backb.configure(state="disabled")
        backb.pack_forget()
        i=0
        try:
            with open(fname, 'a') as out:
                for entry in sysloglive.syslog():
                    i=i+1
                    text.configure(text=f'{i} lines of Syslogs written')
                    out.write(f'{entry}\n')
        except:
            text.configure(text=f'{i} lines of Syslogs written to:\n{fname}')
            log(f'{i} lines of Syslogs written to: {fname}')
            startb.pack_forget()
            backb.configure(state="normal")
            backb.pack(pady=20)


# Call the iTunes Backup
    def show_iTunes_bu(self):
        self.perf_iTunes_bu("iTunes")

# Call the advanced Backup in UFADE-Mode
    def show_logicalplus(self, **kwargs):
        # Defaults
        params = {"incl_ul": "off", "keep_bu": "off", "incl_crash": "on", "incl_media": "on", "incl_apps": "on", "keep_ul": "off"}
        params.update(kwargs)
        self.perf_logical_plus("UFADE", **params)

# Call the advanced Backup in UFED-Mode
    def show_ufed(self, **kwargs):
        # Defaults
        params = {"incl_ul": "off", "keep_bu": "off", "incl_crash": "off", "incl_media": "on", "incl_apps": "on", "keep_ul": "off"}
        params.update(kwargs)
        self.perf_logical_plus("UFED", **params)

# Call the advanced Backup in UFADE-Mode
    def show_prfs(self, **kwargs):
        # Defaults
        params = {"incl_ul": "on", "keep_bu": "off", "incl_crash": "on", "incl_media": "on", "incl_apps": "on", "keep_ul": "off"}
        params.update(kwargs)
        self.perf_logical_plus("PRFS", **params)

# Check, if the device has a backup password and set one
    def check_encryption(self, change):
        try:
            if no_escrow == True:
                UFADEMobilebackup2Service(lockdown).change_password(new="12345")
            else:
                Mobilebackup2Service(lockdown).change_password(new="12345")
            change.set(1)
        except Exception as e:
            e = str(e)
            if "device is locked" in e or "PasswordProtected" in e:
                change.set(3)
            elif "Cannot parse a NULL" in str(e):
                change.set(1)
            else:
                print(e)
                change.set(2)


# Try to deactivate encryption after the Backup is complete
    def deactivate_encryption(self, change, text=None):
        global bu_pass
        try:
            if bu_pass != "12345":
                UFADEMobilebackup2Service(lockdown).change_password(old="12345", new=bu_pass)
            else:
                UFADEMobilebackup2Service(lockdown).change_password(old="12345") 
            change.set(1)
        except:
            change.set(2)
        if text != None:
            if change.get() == 1:
                text.configure(text="Backup password got removed.\nBackup complete.")
            else:
                text.configure(text="Backup password could not be removed.\nBackup complete.")  
        else:
            pass

# Progress output for iTunes Backup
    def show_process(self,x, progress, text, change, beep_timer, setext):
        global bu_fin
        beep_timer.cancel()
        setext.configure(text="Backup in progress.\nDo not disconnect the device.") 
        proc = x / 100
        progress.set(proc)
        text.configure(text=f"{int(x)}%")
        progress.update()
        text.update()
        if x >= 99:
            bu_fin = True
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

# Start a thread for the known password flow
    def call_known_pw(self, passwordbox, pw_found, okbutton, abort, text):
        known = threading.Thread(target=lambda: self.password_known(passwordbox, pw_found, okbutton, abort, text))
        known.start() 

# Function to check the possibly known backup-password
    def password_known(self, passwordbox, pw_found, okbutton, abort, text):
        pw=passwordbox.get()
        global bu_pass
        try:
            okbutton.configure(state="disabled")
            text.configure(text="Checking password...")
            if no_escrow == True:
                UFADEMobilebackup2Service(lockdown).change_password(old=pw, new="12345")                     #Try to deactivate backup encryption with the given password
            else:
                Mobilebackup2Service(lockdown).change_password(old=pw, new="12345")
            bu_pass = pw
            passwordbox.pack_forget()
            okbutton.pack_forget()
            abort.pack_forget()
            text.configure(text=f"Backup password: 12345 \nStarting Backup.\nUnlock device with PIN/PW")
            log(f"Provided correct backup password: {pw}")
            pw_found.set(1)
        except Exception as e:
            if "Cannot parse a NULL" in str(e):
                text.configure(text=f"Backup password: 12345 \nStarting Backup.\nUnlock device with PIN/PW")
                log(f"Provided correct backup password: {pw}")
                pw_found.set(1)
            else:
                print(e)
                text.configure(text="Wrong password.\nProvide the correct backup password:\n(UFADE sets this to \"12345\")")
                log(f"Provided incorrect backup password: {pw} or device error (MDM)")
                okbutton.configure(state="normal")
                return()

# Filedialog for selecting the password-list for the backup password
    def pw_file_call(self):
        global pw_file
        if platform.uname().system == 'Linux':
            import crossfiledialog
            pw_file = crossfiledialog.open_file()
        else:
            pw_file = ctk.filedialog.askopenfilename()

# Actually bruteforcing the backup password
    def brute_bu_pw(self, pw_list, progress, prog_text, text, pw_count, pw_found):
        global bu_pass
        pw_num = 0
        pw_pro = 0
        for pw in pw_list:
            progress.set(pw_pro)
            prog_text.configure(text=f"{int(pw_pro*100)}%")
            progress.update()
            prog_text.update()                   
            try: 
                UFADEMobilebackup2Service(lockdown).change_password(old=pw, new="12345")
                text.configure(text="Password found: " + pw)
                bu_pass = pw
                log(f"Found correct backup password: {pw} via bruteforce")
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
        log("Started iTunes Backup")
        m = mode
        global notify
        global bu_fin
        self.pw_found = ctk.IntVar(self,0)
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text=f"{m} Backup", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
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
            self.change.set(0)     

        elif self.change.get() == 3:
            self.change.set(0)            
            if no_escrow:
                self.text.configure(text="Device connection keys (escrow_bag) are missing.\nMake sure the device is unlocked while performing a backup.")
            else:
                self.text.configure(text="An error occured.\nMake sure the device is unlocked while performing a backup.")
                
            self.after(200, ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.pw_found.set(2)).pack(pady=10))
            self.wait_variable(self.pw_found)
            self.switch_menu("AcqMenu")
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
                self.abort = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, command=lambda: self.pw_found.set(2))
                self.abort.pack(side="bottom", ipadx=(140), pady=(0, 260), padx=(0,40))
                self.wait_variable(self.pw_found)
                if self.pw_found.get() == 2:
                    self.switch_menu("AcqMenu")
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
                                    log("Starting Backup password bruteforce with provided dictionary")
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
                            log(f"Starting Backup password bruteforce with file: {pw_file}")
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
            if no_escrow == True:
                startbu = threading.Thread(target=lambda:UFADEMobilebackup2Service(lockdown).backup(full=True, progress_callback=lambda x: self.show_process(x, self.progress, self.prog_text, self.change, beep_timer, self.text)))
            else:
                startbu = threading.Thread(target=lambda:Mobilebackup2Service(lockdown).backup(full=True, progress_callback=lambda x: self.show_process(x, self.progress, self.prog_text, self.change, beep_timer, self.text)))
            startbu.start()
            self.check_if_done(startbu, self.change)
            self.wait_variable(self.change)
            self.after(500, save_info())
            self.prog_text.pack_forget()
            self.progress.pack_forget()
            if bu_fin == True:
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
                        shutil.move(udid, f'{udid}_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}')
                        self.after(500, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))
                else:
                    pass
                bu_fin = False
            else:
                self.text.configure(text="Error while performing iTunes Backup!\nPlease try again.")
                self.after(500, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))
                self.change.set(0)
                return()        
        else:
            pass

# Advanced Logical Backup Fuctions

# Prepare for Backup decryption
    def init_backup_decrypt(self, change, udid, bu_pass="12345", backuproot="./"):
        global b
        global backupfiles
        try:
            b = iOSbackup(udid=udid, cleartextpassword=bu_pass, derivedkey=None, backuproot=backuproot)                           #Load Backup with Password
            key = b.getDecryptionKey()                                                                                      #Get decryption Key
            b = iOSbackup(udid=udid, derivedkey=key, backuproot=backuproot)                                                       #Load Backup again with Key
            backupfiles = pd.DataFrame(b.getBackupFilesList(), columns=['backupFile','domain','name','relativePath'])
            change.set(1)
        except:
            change.set(2)

# Decrypting / "unbacking" the Backup
    def decrypt_itunes(self, b, backupfiles, progress, prog_text, line_list, line_cnt, d_nr, change, l_type="default", tar=None, zip=None):
        unback_path = {
            "KeychainDomain": "/var/Keychain",
            "CameraRollDomain": "/var/mobile",
            "MobileDeviceDomain": "/var/MobileDevice",
            "WirelessDomain": "/var/wireless",
            "InstallDomain": "/var/installd",
            "KeyboardDomain": "/var/mobile",
            "HomeDomain": "/var/mobile",
            "SystemPreferencesDomain": "/var/preferences",
            "DatabaseDomain": "/var/db",
            "TonesDomain": "/var/mobile",
            "RootDomain": "/var/root",
            "BooksDomain": "/var/mobile/Media/Books",
            "ManagedPreferencesDomain": "/var/Managed Preferences",
            "HomeKitDomain": "/var/mobile",
            "MediaDomain": "/var/mobile",
            "HealthDomain": "/var/mobile/Library",
            "ProtectedDomain": "/var/protected",
            "NetworkDomain": "/var/networkd/",
            "AppDomain": "/var/mobile/Containers/Data/Application",
            "AppDomainGroup": "/var/mobile/Containers/Shared/AppGroup",
            "AppDomainPlugin": "/var/mobile/Containers/Data/PluginKitPlugin",
            "SysContainerDomain": "/var/containers/Data/System",
            "SysSharedContainerDomain": "/var/containers/Shared/SystemGroup"
        }

        #all_apps = installation_proxy.InstallationProxyService(lockdown).get_apps()
        global all_apps
        if "all_apps" in globals():
            pass
        else:
            all_apps = []
        log("Starting Backup decryption")
        MIN_TS = time.mktime((1980, 1, 1, 0, 0, 0, 0, 1, -1))
        for file in line_list:
            fileout = file
            if platform.uname().system == 'Windows':
                fileout = re.sub(r"[?%*:|\"<>\x7F\x00-\x1F]", "-", file)
                if file != fileout:
                    log(f"Renamed {file} to {fileout}")
            d_nr += 1
            dpro = int(100*(d_nr/line_cnt))
            progress.set(dpro/100)
            prog_text.configure(text=f"{int(dpro)}%")
            progress.update()
            prog_text.update()
            filedomain = backupfiles.loc[backupfiles['relativePath'] == file, 'domain'].iloc[0]
            try:
                b.getFileDecryptedCopy(relativePath=file, targetName=fileout, targetFolder=os.path.join(".tar_tmp", "itunes_bu"))               #actually decrypt the backup-files
                file_path = os.path.join('.tar_tmp', 'itunes_bu', fileout)
                stat = os.stat(file_path)
                if stat.st_mtime < MIN_TS:
                    os.utime(file_path, (stat.st_atime, MIN_TS))
                if l_type == "PRFS":
                    if "AppDomain-" in filedomain:
                        appfile = filedomain.split("-", 1)[1]
                        try:
                            tarpath = all_apps.get(appfile)['Container']
                        except:
                            tarpath = f"/private{unback_path['AppDomain']}/{appfile}"
                    elif "AppDomainGroup-" in filedomain:
                        appfile = filedomain.split("-")[1]
                        tarpath = tarpath = f"/private{unback_path['AppDomainGroup']}/{appfile}"
                        for app in all_apps:
                            try:
                                if all_apps[app]['GroupContainers'].get(appfile) is not None:
                                        tarpath = all_apps[app]['GroupContainers'].get(appfile)
                                        break
                                else:
                                    tarpath = f"/private{unback_path['AppDomainGroup']}/{appfile}"
                            except:
                                tarpath = f"/private{unback_path['AppDomainGroup']}/{appfile}"
                    elif "AppDomainPlugin-" in filedomain:
                        appfile = filedomain.split("-")[1]
                        tarpath = f"/private{unback_path['AppDomainPlugin']}/{appfile}"
                    elif "SysContainerDomain-" in filedomain:
                        appfile = filedomain.split("-")[1]
                        tarpath = f"/private{unback_path['SysContainerDomain']}/{appfile}"
                    elif "SysSharedContainerDomain-" in filedomain:
                        appfile = filedomain.split("-")[1]
                        tarpath = f"/private{unback_path['SysSharedContainerDomain']}/{appfile}"
                    else:
                        tarpath = f"/private{unback_path[filedomain]}"
                    tarfile_path = posixpath.join(tarpath, file)
                    unback_set.add(tarfile_path)
                    if "/private/var/mobile/Media" in tarfile_path:
                        m_unback_set.add(tarfile_path.replace("/private/var/mobile/Media", ""))
                    if tarfile_path == "/private/var/mobile/Media":
                        pass
                    else:
                        zip.write(file_path, os.path.join(tarpath, file))
                else:
                    tar.add(file_path, arcname=os.path.join("iTunes_Backup/", 
                        backupfiles.loc[backupfiles['relativePath'] == file, 'domain'].iloc[0], file), recursive=False)         #add files to the TAR
                try: os.remove(file_path)                                                                                       #remove the file after adding
                except: pass
            except Exception as e:
                log(f"Error while decrypting file:{file.encode('cp1252', errors='ignore').decode('cp1252')} - {e}")
        change.set(1) 

# Decrypt, don't unback
    def only_decrypt_itunes(self, b, backupfiles, progress, prog_text, line_list, line_cnt, d_nr, change, src, folder=None):
        os.makedirs(folder, exist_ok=True)
        log("Starting Backup decryption")
        for file in line_list:
            fileout = file
            d_nr += 1
            dpro = int(100*(d_nr/line_cnt))
            progress.set(dpro/100)
            prog_text.configure(text=f"{int(dpro)}%")
            progress.update()
            prog_text.update()
            sha_name = backupfiles.loc[backupfiles['relativePath'] == file, 'backupFile'].iloc[0]
            target_dir = os.path.join(folder, sha_name[:2])
            os.makedirs(target_dir, exist_ok=True)
            try:
                b.getFileDecryptedCopy(relativePath=file, targetName=sha_name, targetFolder=target_dir)
            except Exception as e:
                log(f"Error while decrypting file:{file.encode('cp1252', errors='ignore').decode('cp1252')} - {e}")
            
        for name in os.listdir(src):
            try:
                src_path = os.path.join(src, name)
                if os.path.isfile(src_path):
                    if not "Manifest.db" in src_path:
                        shutil.copy2(src_path, os.path.join(folder, name))
            except:
                pass
        try:
            shutil.copy2(b.manifestDB, os.path.join(folder, "Manifest.db"))
        except:
            pass
        for dirpath, dirnames, filenames in os.walk(folder, topdown=False):
            if not dirnames and not filenames:
                os.rmdir(dirpath)
        change.set(1) 

# Fallback decryption function for older devices
    def decrypt_old_itunes(self, tar, change):
        log("Using fallback decryption method")
        try:
            bu = Backup.from_path(backup_path=udid, password="12345")
            unback_alt(bu, os.path.join(".tar_tmp", "itunes_bu"))
            tar.add(".tar_tmp/itunes_bu", arcname="iTunes_Backup/", recursive=True)
            change.set(1)
        except:
            log("Error decrypting backup")
            change.set(2)

# Only decrypt Whatsaap (TESS/PuMA)
    def decrypt_whatsapp(self, change, wachange):
        log("Started Whatsapp extraction")
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
            log(f"Error while extracting {app} data")
            pass
        if wachange.get() == 3:
            wachange.set(2)
            self.decrypt_whatsapp(change, wachange)
        else:l_type="default"
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
                self.decrypt_whatsapp(change, wachange)
                #self.waitvar(self.wabwait)
            if finish == True:
                self.after(100, lambda: self.text.configure(text="Whatsapp files extracted.")) 
            change.set(1)

# Zip thread helper
    def zip_file(self, zip, source_file, arcname, lock):
        with lock:
            zip.write(source_file, arcname=arcname)


 # Move the backup files to a zip archive   
    def zip_itunes(self, zip, change):
        base = udid
        lock = threading.Lock()
        with ThreadPoolExecutor() as executor:
            tasks = []
            for root, dirs, files in os.walk(base):
                for file in files:
                    source_file = os.path.join(root, file)
                    filename = os.path.relpath(source_file, base)
                    arcname = os.path.join("iPhoneDump/Backup Service", udid, "Snapshot", filename)
                    tasks.append(executor.submit(self.zip_file, zip, source_file, arcname, lock))
            for task in tasks:
                    task.result()  
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
                    if l_type == "PRFS":
                        app_dest = os.path.join(str((apps.get(app)['EnvironmentVariables'])['CFFIXED_USER_HOME'])[1:], "Documents/")
                        for root, dirs, files in os.walk(file_path):
                            for file in files:
                                source_file = os.path.join(root, file)
                                filename = os.path.relpath(source_file, file_path)
                                app_arc = posixpath.join(app_dest, filename)
                                if app_arc not in unback_set and os.path.isfile(file_path):
                                    zip.write(file_path, app_arc)
                                else:
                                    pass
                    else:
                        tar.add(file_path, arcname=os.path.join("App_Share/", app, str((apps.get(app)['EnvironmentVariables'])['CFFIXED_USER_HOME'])[1:], "Documents/"), recursive=True)
                else:
                    for root, dirs, files in os.walk(file_path):
                        for file in files:
                            source_file = os.path.join(root, file)
                            filename = os.path.relpath(source_file, file_path)
                            try:
                                zip.write(source_file, os.path.join("iPhoneDump/Applications/", app, filename))
                            except:
                                log(f"Error zipping file {filename}")
                                pass

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

# Check, if the device is locked
    def check_lock(self, change, text):
        try:
            check_apps = installation_proxy.InstallationProxyService(lockdown).get_apps()
            change.set(1)
            return() 
        except exceptions.PasswordRequiredError:
            print("Device locked")
            text.configure(text="The device is locked. Unlock the device to continue.")
            text.update()
            while True:
                try:
                    self.after(3000)
                    check_apps = installation_proxy.InstallationProxyService(lockdown).get_apps()
                    change.set(2)
                    break 
                except:
                    pass
        finally:
            return()

# Actually perform the advanced logical backup
    def perf_logical_plus(self, t, incl_ul, keep_bu, incl_crash, incl_media, incl_apps, keep_ul):
        global lockdown
        l_type = t
        log(f"Starting logical+ backup (type={l_type})")
        #create temp folder for files to zip/tar
        try: os.mkdir(".tar_tmp")                                                                                               
        except: pass
        #create folder for decrypted backup
        if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
            self.change = ctk.IntVar(self, 0)
            ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
            ctk.CTkLabel(self.dynamic_frame, text="PRFS Backup", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
            self.text = ctk.CTkLabel(self.dynamic_frame, text="Performing PRFS-Extraction without Backup.", width=585, height=60, font=self.stfont, anchor="w", justify="left")
            self.text.pack(anchor="center", pady=25)
            self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
            self.prog_text.pack() 
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
            self.progress.set(0)
            self.progress.pack() 
        else:
            try: os.mkdir(".tar_tmp/itunes_bu")                                                                                     
            except: pass
        now = datetime.now()
        if l_type == "PRFS":
            bu_name = "PRFS"
        else:
            bu_name = "Logical+"
        if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
            pass
        else:
            self.perf_iTunes_bu(bu_name)
            if self.pw_found.get() == 2:
                return()                                                                                                  
        
        if l_type != "UFED":
            if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
                zipname = f'{udid}_prfs_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}'                                                     
                zip = zipfile.ZipFile(f'{zipname}.zip', "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1)
                tar = None
            else:
                self.after(10, lambda: self.text.configure(text="Decrypting iTunes Backup: "))
                self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
                self.prog_text.pack() 
                self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
                self.progress.set(0)
                self.progress.pack()
                self.change.set(0)
                panda_backup = threading.Thread(target=lambda: self.init_backup_decrypt(self.change, udid))
                panda_backup.start()
                self.wait_variable(self.change)
                if self.change.get() == 1:
                    #get amount of lines (files) of backup
                    line_list = []
                    line_cnt = 0
                    for line in backupfiles['relativePath']:                                                                        
                        if(line not in line_list):
                            line_cnt += 1
                            line_list.append(line)
                    d_nr = 0
                    self.change.set(0)                                                                     
                    if l_type == "PRFS":
                        zipname = f'{udid}_prfs_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}'                                                     
                        zip = zipfile.ZipFile(f'{zipname}.zip', "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1)
                        tar = None
                        decrypt = threading.Thread(target=lambda: self.decrypt_itunes(b, backupfiles, self.progress, self.prog_text, line_list, line_cnt, d_nr, self.change, l_type, zip=zip))
                        decrypt.start()
                    else:
                        tar = tarfile.open(f'{udid}_logical_plus_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}.tar', "a:")
                        zip = None
                        decrypt = threading.Thread(target=lambda: self.decrypt_itunes(b, backupfiles, self.progress, self.prog_text, line_list, line_cnt, d_nr, self.change, l_type, tar=tar))
                        decrypt.start()

                else:
                    self.text.configure(text="Decrypting iTunes Backup - this may take a while.")
                    self.text.update()
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
                #remove the backup folder
                try: shutil.rmtree(".tar_tmp/itunes_bu")
                except: pass    
                if keep_bu == "off":                                                                            
                    try: shutil.rmtree(udid)
                    except: pass
                else:
                    try: os.rename(udid, f'{udid}_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}')
                    except: pass
                if self.change.get() == 2:
                    self.after(50)
                    self.text.configure(text="An error occured.\nTry again and make sure the device stays unlocked.")
                    self.text.update()
                    self.progress.pack_forget()
                    self.prog_text.pack_forget()
                    self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))
                    return
                        
        else:
            #create ZIP-File for CLB PA (TAR-handling isn't as good here)
            zipname = f'Apple_{hardware.upper()}_{dev_name}_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}'                                                     
            zip = zipfile.ZipFile(f'{zipname}.zip', "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1)
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
            #delete the backup after zipping
            if keep_bu == "off":
                try: shutil.rmtree(udid)   
                except: pass
            else:
                try: os.rename(udid, f'{udid}_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}')
                except: pass

        if incl_ul == "on":
            try:
                self.after(100, lambda: self.text.configure(text="Collecting Unified Logs - this may take a while."))
                self.change.set(0)
                self.prog_text.pack_forget()
                self.progress.pack_forget()
                self.prog_text = ctk.CTkLabel(self.dynamic_frame, text=" ", width=585, height=20, font=self.stfont, anchor="w", justify="left")
                self.prog_text.pack()
                self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
                self.progress.pack()
                self.progress.start()
                self.prfs_ul = threading.Thread(target=lambda: self.collect_ul(time=None, text=self.text, waitul=self.change, mode="PRFS"))
                self.prfs_ul.start() 
                self.wait_variable(self.change)
                if self.change.get() == 2:
                    log("Error while collecting Unified Logs.")
                    self.change.set(0)
                else:
                    if l_type == "PRFS":
                        self.after(100, lambda: self.text.configure(text="Include Unified Logs in the archive."))
                        self.ul_zip = threading.Thread(target=lambda: self.zip_ul(zip=zip, text=self.text, waitul=self.change)) 
                        self.ul_zip.start()
                        self.wait_variable(self.change)
                        if keep_ul == "off":
                            try: shutil.rmtree(f"{udid}.logarchive") 
                            except: pass
            except:
                pass                                                                                            

        #Gather Media Directory
        if incl_media == "on":
            try: os.mkdir(".tar_tmp/media")
            except: pass
            self.change.set(0)
            self.lockcheck = threading.Thread(target=lambda: self.check_lock(self.change, self.text))
            self.lockcheck.start()
            self.wait_variable(self.change)
            self.after(200)
            if self.change.get() == 2:
                lockdown = create_using_usbmux()
            self.prog_text.configure(text="0%")
            self.progress.pack_forget()
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
            self.progress.set(0)
            self.progress.pack()

            self.change.set(0)
            if l_type != "UFED":
                if l_type == "PRFS":
                    self.tar_media = threading.Thread(target=lambda: media_export(l_type=l_type, dest=".tar_tmp/media", archive=zip, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change))
                else:
                    self.tar_media = threading.Thread(target=lambda: media_export(l_type=l_type, dest=".tar_tmp/media", archive=tar, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change))
                self.tar_media.start()
            else:
                self.zip_media = threading.Thread(target=lambda: media_export(l_type=l_type, dest=".tar_tmp/media", archive=zip, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change))
                self.zip_media.start()
            self.wait_variable(self.change)
            #remove media-folder
            shutil.rmtree(".tar_tmp/media")                                                                                       

        #Gather Shared App-Folders
        if incl_apps == "on":
            self.change.set(0)
            self.lockcheck = threading.Thread(target=lambda: self.check_lock(self.change, self.text))
            self.lockcheck.start()
            self.wait_variable(self.change)
            self.after(100)
            if self.change.get() == 2:
                lockdown = create_using_usbmux()
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
            if incl_crash == "on":
                self.change.set(0)
                self.lockcheck = threading.Thread(target=lambda: self.check_lock(self.change, self.text))
                self.lockcheck.start()
                self.wait_variable(self.change)
                self.text.configure(text="Performing Extraction of Crash Reports")
                self.prog_text.configure(text="0%")
                self.progress.pack_forget() 
                self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
                self.progress.set(0)
                self.progress.pack()
                self.after(100)
                lockdown = create_using_usbmux()
                self.change.set(0)
                if l_type == "PRFS":
                    tarpath = "/private/var/mobile/Library/Logs/CrashReporter"
                else:
                    tarpath = "/Crash"
                self.crash_start = threading.Thread(target=lambda: crash_report(crash_dir=".tar_tmp/Crash", change=self.change, progress=self.progress, prog_text=self.prog_text, l_type=l_type, tar=tar, zip=zip, tarpath=tarpath))
                self.crash_start.start()
                self.wait_variable(self.change)
                if l_type != "PRFS":
                    self.progress.pack_forget()
                    self.prog_text.pack_forget()
                self.after(100)
                shutil.rmtree(".tar_tmp/Crash")

        #Add Bundle Files for PRFS
            if l_type == "PRFS":

                def bytes_to_base64(obj):
                    if isinstance(obj, bytes):
                        return base64.b64encode(obj).decode("ascii")
                    raise TypeError

                try:
                    self.progress.pack_forget()
                    self.prog_text.pack_forget()
                except:
                    pass
                self.prog_text = ctk.CTkLabel(self.dynamic_frame, text=" ", width=585, height=20, font=self.stfont, anchor="w", justify="left")
                self.prog_text.pack()
                self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
                self.progress.pack()
                self.progress.start()

                self.text.configure(text="Performing Extraction of additional Files via Live-Commands")
                self.text.update()
                self.change.set(0)

                def additional_prfs():
                    appinfo = installation_proxy.InstallationProxyService(lockdown).get_apps(application_type="Any", calculate_sizes=True)

                    try:
                        json_bytes = json.dumps(appinfo, default=bytes_to_base64)
                        zip.writestr("_ufade_extra/app_info.json", json_bytes)
                    except Exception as e:
                        pass
                        #print(e)
                    try:
                        appfile = installation_proxy.InstallationProxyService(lockdown).browse(attributes=['CFBundleIdentifier', 'iTunesMetadata', 'ApplicationDSID', 'ApplicationSINF', 'ApplicationType', 'CFBundleDisplayName', 'CFBundleExecutable', 'CFBundleName', 'CFBundlePackageType', 'CFBundleShortVersionString', 'CFBundleVersion', 'Container', 'GroupContainers', 'MinimumOSVersion', 'Path', 'UIDeviceFamily', 'DynamicDiskUsage', 'StaticDiskUsage', 'UIFileSharingEnabled'])
                        for app in appfile:
                            try:
                                if "Bundle" in app['Path']:
                                    bpath = app['Path']
                                    bundlepath = f'{bpath.strip("/")}/'
                                    zip.writestr(zipfile.ZipInfo(bundlepath), '')
                                    try:
                                        pkginfo = app['CFBundlePackageType']
                                        pkginfo = f"{pkginfo:{'?'}<8}"
                                        pkgfile = os.path.join(".tar_tmp", "PkgInfo")
                                        pkgpath = os.path.join(bundlepath, "PkgInfo")
                                        with open(pkgfile, "w") as file:
                                            file.write(pkginfo)
                                        zip.write(pkgfile, pkgpath)
                                        os.remove(pkgfile)
                                    except:
                                        pass                    
                                    try:
                                        itunesplist = app['iTunesMetadata']
                                        itunes_path = "/".join(list(bpath.split('/')[0:-1])) 
                                        metafile = os.path.join(".tar_tmp", "iTunesMetadata.plist")
                                        with open(metafile, "wb") as file:
                                            file.write(itunesplist)
                                        zip.write(metafile, f"{itunes_path}/iTunesMetadata.plist")
                                        os.remove(metafile)
                                    except:
                                        pass
                                    try:
                                        appsinf = app['ApplicationSINF']
                                        appsinfname = f"{app['CFBundleExecutable']}.sinf"
                                        appsinfpath = os.path.join(bundlepath, "SC_Info", appsinfname)
                                        sinffile = os.path.join(".tar_tmp", appsinfname)
                                        with open(sinffile, "wb") as file:
                                            file.write(appsinf)
                                        zip.write(sinffile, appsinfpath)
                                        os.remove(sinffile)
                                    except:
                                        pass
                                try:
                                    iconname = f"{app['CFBundleIdentifier']}.png"
                                    png_data = SpringBoardServicesService(lockdown).get_icon_pngdata(app['CFBundleIdentifier'])
                                    zip.writestr(f"_ufade_extra/icons/{iconname}", png_data)
                                except Exception as e:
                                    pass
                                    log(f"Error with app {app['CFBundleIdentifier']}: {e}")
                                    #print(e)
                            except:
                                pass
                    except:
                        pass
                    self.change.set(1)
                prfs_additional = threading.Thread(target=additional_prfs)
                prfs_additional.start()
                self.wait_variable(self.change)


        #Gather device information as device_values.plist for UFD-ZIP
        else:
            lockdown = create_using_usbmux()
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

        self.progress.pack_forget()
        self.prog_text.pack_forget()
        
        if l_type != 'UFED':
            if l_type == 'PRFS':
                zip.close()
            else:
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
            self.hashf = threading.Thread(target=lambda: self.hash_ufd(change=self.change, zipname=f'{zipname}.zip'))
            self.hashf.start()
            self.wait_variable(self.change)
            with open(f'{zipname}.ufd', "w") as ufdf:
                ufdf.write("[DeviceInfo]\nIMEI1=" + imei + "\nIMEI2=" + imei2 + "\nModel=" + product + "\nOS=" + dversion + "\nVendor=Apple\n\n[Dumps]\nFileDump=" + zipname +
                ".zip\n\n[ExtractionStatus]\nExtractionStatus=Success\n\n[FileDump]\nType=ZIPfolder\nZIPLogicalPath=iPhoneDump\n\n[General]\nAcquisitionTool=UFADE\nBackupPassword=" + "12345" + "\nConnectionType=Cable No. 210 or Original Cable\nDate=" + begin + "\nDevice=" + d_class.upper() + "\nEndTime=" + e_end + "\nExtractionNameFromXML=File System\nExtractionType=AdvancedLogical\nFullName=" +
                hardware.upper() + " " + dev_name + "\nGUID=" + udid + "\nInternalBuild=\nIsEncrypted=True\nIsEncryptedBySystem=True\nMachineName=\nModel=" + hardware.upper() + " " + dev_name + "\nUfdVer=1.2\nUnitId=\nUserName=\nVendor=Apple\nVersion=other\n\n[SHA256]\n" + zipname + ".zip=" + z_hash.upper() + "")
            self.progress.pack_forget()

        if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
            pass
        else:
            self.text.configure(text="Backup complete!\nTrying to deactivate Backup Encryption again. \nUnlock device with PIN/PW if prompted")
            self.change.set(0)
            beep_timer = threading.Timer(13.0,self.notification)  
            beep_timer.start()
            remove_enc = threading.Thread(target=lambda: self.deactivate_encryption(change=self.change, text=self.text))
            remove_enc.start()
            self.wait_variable(self.change)
            beep_timer.cancel()   
        self.text.configure(text="Logical+ Backup completed!")
        log("Logical+ Backup completed!")
        if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
            self.after(500, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("ReportMenu")).pack(pady=40))
        else:
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
                        "com.apple.mobile.iTunes.accessories", "com.apple.mobile.iTunes.store", "com.apple.mobile.internal", "com.apple.mobile.lockdown_cache", "com.apple.mobile.lockdownd",
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
            ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
            ctk.CTkLabel(self.dynamic_frame, text="PuMA Backup", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
            self.text = ctk.CTkLabel(self.dynamic_frame, text="WhatsApp not installed on device!", width=585, height=60, font=self.stfont, anchor="w", justify="left")
            self.text.pack(anchor="center", pady=25)
            self.after(500, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AdvMenu")).pack(pady=40))   

        else:
            self.wachange = ctk.IntVar(self, 0)
            self.label1 = ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont)
            self.label2 = ctk.CTkLabel(self.dynamic_frame, text="PuMA Backup", height=60, width=585, font=("standard",24), justify="left")
            self.label1.pack(anchor="w")
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
            self.label2.pack_forget()
            self.label1.pack_forget()
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
            self.tess_init = threading.Thread(target=lambda: self.init_backup_decrypt(self.change, udid))
            self.tess_init.start()
            self.waitvar(self.change)
            if self.change.get() == 1:
                self.change.set(0)
                self.tess_backup = threading.Thread(target=lambda: self.decrypt_whatsapp(self.change, self.wachange))
                self.tess_backup.start()
                self.waitvar(self.change)
            elif self.change.get() == 2:
                self.change.set(0)
                self.text.configure(text="Something went wrong. Please try again.")
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
            log("FFS extraction started")
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
                    if ffs_pro >= 0.99:
                        ffs_pro = 0.99
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
            log("FFS extraction completed")
            self.change.set(1)
        except:
            text.configure(text="Error connecting to SSH. The device has to be in jailbroken state and SSH has to be installed.")
            self.change.set(1)

    def perf_jailbreak_ssh_dump(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Filesystem Backup", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Provide the SSH parameters. The default values are suitable for Checkra1n and Palera1n: ", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.change = ctk.IntVar(self, 0)
        self.backb = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, fg_color="#8c2c27", command=lambda: (self.switch_menu("AcqMenu"), self.change.set(2)))
        self.backb.pack(side="bottom", pady=(0,400))
        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.choose_jb_params(self.text, self.portbox, self.userbox, self.pwbox, self.pathbox, self.backb))
        self.okbutton.pack(side="bottom", pady=(10))
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
        if self.change.get() == 2:
            return
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AcqMenu")).pack(pady=40))   

    def choose_jb_params(self, text, portbox, userbox, pwbox, pathbox, backb):
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
        self.backb.pack_forget()
        perfssh = threading.Thread(target=lambda: self.ssh_dump(text, scr_prt, remote_folder, user, pwd))
        perfssh.start()

# Network Sniffer Display
    def show_sniffer(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Capture Device Traffic", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Set the number of packets to sniff (0 is endless):", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.change = ctk.IntVar(self, 0)
        self.packetbox = ctk.CTkEntry(self.dynamic_frame, width=80, height=20, corner_radius=0, placeholder_text="0")
        self.packetbox.bind(sequence="<Return>", command=lambda x: self.call_ncapture(self.packetbox, self.okbutton, self.text, self.change))
        self.packetbox.insert(0, string="0")
        self.packetbox.pack(side="left", pady=(0,370), padx=(230,0))  
        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.call_ncapture(self.packetbox, self.okbutton, self.backb, self.text, self.change))
        self.okbutton.pack(side="left", pady=(0,370), padx=(20, 0))
        self.backb = ctk.CTkButton(self.dynamic_frame, text="Back", font=self.stfont, fg_color="#8c2c27", command=lambda: self.change.set(2))
        self.backb.pack(pady=(0,370), padx=(10,100))
        self.waitvar(self.change)
        if self.change.get() == 2:
            self.after(100, lambda: self.switch_menu("AdvMenu"))
            return 

        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AdvMenu")).pack(pady=40))   

# Call the sniffing function as a thread with provided user input
    def call_ncapture(self, packetbox, okbutton, backb, text, change):
        self.stop_event.clear()
        packnum = packetbox.get()
        packetbox.pack_forget()
        okbutton.pack_forget()
        backb.pack_forget()
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
            pname = f'{udid}_{str(datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))}.pcap'            
            with open(pname, "wb") as pcap_file:
                serv_pcap.write_to_pcap(pcap_file, packets_generator)
            text.configure(text="Sniffing process stopped. " + str(count) + " packages received." )
        except ValueError: 
            text.configure(text="Invalid input. Provide digits only.")
        except:
            text.configure(text=f"Sniffing process stopped.\nTraffic has been written to: {pname}")
        finally:
            change.set(1)
        change.set(1)
        return

# Media Extracton for Watches
    def show_media(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Extract AFC-Media files", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Performing AFC Extraction of Mediafiles", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        folder = f'Media_{udid}_{str(datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))}'
        try: os.mkdir(folder)
        except: pass
        self.change = ctk.IntVar(self, 0)
        self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.prog_text.pack()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
        self.progress.set(0)
        self.prog_text.configure(text="0%")
        self.progress.pack()
        self.tar_media = threading.Thread(target=lambda: media_export(l_type="folder", dest=folder, text=self.text, prog_text=self.prog_text, progress=self.progress, change=self.change, fzip=True))
        self.tar_media.start()
        self.wait_variable(self.change)
        self.text.configure(text="AFC Extraction complete.")
        self.prog_text.pack_forget()
        self.progress.pack_forget()
        if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("WatchMenu")).pack(pady=40))  
        else:
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("AdvMenu")).pack(pady=40)) 
### check start

    def show_report(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Generate UFDR Report", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Provide the case information:", width=585, height=30, font=self.stfont, anchor="w", justify="left")
        self.change = ctk.IntVar(self, 0)
        self.text.pack(anchor="center", pady=25)
        self.casebox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="case number")
        self.casebox.pack(pady=5, padx=30)
        self.namebox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="case name")
        self.namebox.pack(pady=5, padx=30)
        self.evidbox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="evidence number")
        self.evidbox.pack(pady=5, padx=30)  
        self.exambox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="examiner")
        self.exambox.pack(pady=5, padx=30) 
        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.change.set(1))
        self.okbutton.pack(pady=30, padx=100)
        global case_number
        global case_name
        global evidence_number
        global examiner
        if case_number != "":
                self.casebox.insert(0, string=case_number)
        else:
            pass
        if case_name != "":
                self.namebox.insert(0, string=case_name)
        else:
            pass
        if evidence_number != "":
                self.evidbox.insert(0, string=evidence_number)
        else:
            pass
        if examiner != "":
                self.exambox.insert(0, string=examiner)
        else:
            pass
        self.wait_variable(self.change)
        self.text.configure(text="Performing AFC Extraction of Mediafiles", height=60)
        global lockdown
        lockdown = create_using_usbmux()
        self.casebox.pack_forget()
        self.namebox.pack_forget()
        self.evidbox.pack_forget()
        self.exambox.pack_forget()
        self.okbutton.pack_forget()
        self.change.set(0)
        case_number = self.casebox.get()
        case_name = self.namebox.get()
        evidence_number = self.evidbox.get()
        examiner = self.exambox.get()
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
        lockdown = create_using_usbmux()
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
        self.report = threading.Thread(target=lambda: self.watch_report(text=self.text, change=self.change, progress=self.progress, prog_text=self.prog_text, now=now, case_number=case_number, case_name=case_name, evidence_number=evidence_number, examiner=examiner))
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
        global lockdown
        lockdown = create_using_usbmux()
        self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0, mode="indeterminate", indeterminate_speed=0.5)
        self.progress.pack()
        self.progress.start()
        
        sys_diag = False
        diag_pattern = re.compile(r'sysdiagnose_(\d{4}\.\d{2}\.\d{2}_\d{2}-\d{2}-\d{2}\+\d{4})')
        latest_file = None
        latest_date = ""
        for root, dirs, filenames in os.walk(cfolder):
            for filename in filenames:
                if 'sysdiagnose_' in filename and not "IN_PROGRESS_" in filename and filename.endswith("tar.gz"):
                    try:
                        sys_date = diag_pattern.search(filename).group(1)
                        if sys_date > latest_date:
                            latest_date = sys_date
                            latest_file = filename
                            diagfile = os.path.join(root, filename)
                            sys_diag = True
                    except:
                        pass
        if sys_diag == True:
            diagdict = sysdiag(diagfile)
        
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

        try:
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
        except:
            pass

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

        apple_id = ""
        purchasedict = {}
        try: os.mkdir(os.path.join("Report", "files", "Applications"))
        except: pass
        app_report_list = []
        try:
            appfile = installation_proxy.InstallationProxyService(lockdown).browse(attributes=['CFBundleIdentifier', 'iTunesMetadata', 'ApplicationDSID', 'ApplicationSINF', 'ApplicationType', 'CFBundleDisplayName', 'CFBundleExecutable', 'CFBundleName', 'CFBundlePackageType', 'CFBundleShortVersionString', 'CFBundleVersion', 'Container', 'GroupContainers', 'MinimumOSVersion', 'Path', 'UIDeviceFamily', 'DynamicDiskUsage', 'StaticDiskUsage', 'UIFileSharingEnabled'])
        except:
            appfile = []
            
        for app in appfile:
            app_report_dict = {}
            app_report_dict["id"] = str(uuid.uuid4())
            app_report_dict["name"] = app['CFBundleDisplayName']
            appname = app['CFBundleIdentifier']
            try: os.mkdir(os.path.join("Report", "files", "Applications", appname))
            except: pass
            try: 
                itunesplist = app['iTunesMetadata']
                readitunes = plistlib.loads(itunesplist)
                if apple_id == "":
                    apple_id = readitunes['com.apple.iTunesStore.downloadInfo']['accountInfo']['AppleID']
                purchasedict[app["CFBundleIdentifier"]] = readitunes['com.apple.iTunesStore.downloadInfo']['purchaseDate']
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
            try: 
                addition['CFBundleVersion'] = app['CFBundleVersion']
                app_report_dict["version"] = app['CFBundleVersion']
            except: 
                app_report_dict["version"] = "1"
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
            app_report_dict["identifier"] = app['CFBundleIdentifier']
            app_report_list.append(app_report_dict)
            with open(os.path.join("Report", "files", "Applications", appname, "AdditionInfo.plist"), "wb") as file:
                plistlib.dump(addition, file)

            with open(os.path.join("Report", "files", "Applications", appname, "description.info"), "w") as file:
                file.write(f"Name={app['CFBundleDisplayName'].encode('cp1252', errors='ignore').decode('cp1252')}\n")
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
                file.write(f'<Name sourceValue="CFBundleDisplayName">{app["CFBundleDisplayName"]}</Name>\n')
                file.write(f'<Package sourceValue="CFBundleIdentifier">{app["CFBundleIdentifier"]}</Package>\n')
                try: file.write(f'<iOSValue sourceValue="CFBundlePackageType">{app["CFBundlePackageType"]}</iOSValue>\n')
                except: file.write(f'<iOSValue sourceValue="CFBundlePackageType"></iOSValue>\n')
                try: file.write(f'<Version sourceValue="CFBundleVersion">{app["CFBundleVersion"]}</Version>\n')
                except: file.write('<Version sourceValue="CFBundleVersion">0</Version>\n')
                file.write(f'<iOSValue sourceValue="CFBundleName">{app["CFBundleName"]}</iOSValue>\n')
                try: file.write(f'<iOSValue sourceValue="Container">{app["Container"]}</iOSValue>\n')
                except: file.write('<iOSValue sourceValue="Container"></iOSValue>\n')
                try: file.write(f'<iOSValue sourceValue="Path">{app["Path"]}</iOSValue>\n')
                except: file.write('<iOSValue sourceValue="Path"></iOSValue>\n')
                file.write(f'<iOSValue sourceValue="ApplicationType">{app["ApplicationType"]}</iOSValue>\n')
                try: file.write(f'<MinimumOS sourceValue="MinimumOS">{app["MinimumOS"]}</MinimumOS>\n')
                except: file.write('<MinimumOS sourceValue="MinimumOS"></MinimumOS>\n')
                try: file.write(f'<FileSharing sourceValue="UIFileSharingEnabled">{app["UIFileSharingEnabled"]}</FileSharing>\n')
                except: file.write('<FileSharing sourceValue="UIFileSharingEnabled">0</FileSharing>\n')
                try: file.write(f'<iOSValue sourceValue="ApplicationDSID">{app["ApplicationDSID"]}</iOSValue>\n')
                except: file.write('<iOSValue sourceValue="ApplicationDSID">0</iOSValue>\n')
                try: file.write(f'<AppSize sourceValue="StaticDiskUsage">{app["StaticDiskUsage"]}</AppSize>\n')
                except: file.write('<AppSize sourceValue="StaticDiskUsage">0</AppSize>\n')
                try: file.write(f'<DataSize sourceValue="DynamicDiskUsage">{app["DynamicDiskUsage"]}</DataSize>\n')
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
        begin = str(now.strftime(output_format)) + sign + str(int(utc_offset_hours))

        #End Time for UFD-Report
        end = datetime.now()
        local_timezone = datetime.now(timezone.utc).astimezone().tzinfo
        utc_offset = end.astimezone().utcoffset()
        utc_offset_hours = utc_offset.total_seconds() / 3600
        if utc_offset_hours >= 0:
            sign = "+"
        else:
            sign = "-" 
        e_end = str(end.strftime(output_format)) + sign + str(int(utc_offset_hours))

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
            'name': 'UFADE Report',
            'isCustomName': 'True',
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

        ET.SubElement(metadata, 'item', {
            'name': 'DeviceInfoSelectedManufacturer',
            'sourceExtraction': '0'
        }).text = 'Apple'

        ET.SubElement(metadata, 'item', {
            'name': 'DeviceInfoSelectedDeviceName',
            'sourceExtraction': '0'
        }).text = str(dev_name)

        ET.SubElement(metadata, 'item', {
            'name': 'DeviceInfoConnectionType',
            'sourceExtraction': '0'
        }).text = 'Generic iBus Adapter'

        ET.SubElement(metadata, 'item', {
            'name': 'ProjectStateExtractionId',
            'sourceExtraction': '0'
        }).text = str(udid)

        if d_class == "Watch": 
            os_type = "watchOS"
        elif d_class == "AppleTV":
            os_type = "tvOS"
        elif d_class == "AudioAccessory":
            os_type = "audioOS"
        metadata_device_info = ET.SubElement(project, 'metadata', {'section': 'Device Info'})
        #me_dev_info = {'Serial Number': snr, 'Device Name': name, 'WiFi Address': w_mac, 'Model Number': hardware + ", Model:" + mnr, 'Bluetooth Address': b_mac, 'Device': dev_name, 'Time Zone': d_tz, 'Unique Identifier': udid}
        me_dev_info = {'Device Name': name, 'Device': dev_name, 'Model Number': f'{hardware} , Model: {mnr}', 'MAC (WiFi Address)': w_mac, 'MAC (Bluetooth Address)': b_mac, 'Unique Identifier': udid, 'Unique Chip ID': ecid, 'Serial Number': snr, 'Disk Capacity': f'{disk} GB', 'Software': f'{os_type} {dversion}', 'Buildnumber': build , 'Time Zone': d_tz,}
        if imei != " ":
            me_dev_info['IMEI'] = imei
        else:
            pass
        if apple_id != "":
            me_dev_info['Apple-ID'] = apple_id
        else:
            pass
        try: 
            number = lockdown.get_value(key="PhoneNumber")
            if number == None:
                number = ""
        except: 
            number = ""
        if number != "":
            me_dev_info['Last Number'] = number
        try:
            all = lockdown.all_values.get("CarrierBundleInfoArray")
            if all == None:
                all = ""
        except: 
            all = ""
        if all != "":
            for entry in all:
                try: 
                    me_dev_info['ICCID'] = entry["IntegratedCircuitCardIdentity"]
                    me_dev_info['IMSI'] = entry["InternationalMobileSubscriberIdentity"]
                    me_dev_info['MCC'] = entry["MCC"]
                    me_dev_info['MNC'] = entry["MNC"]
                except:
                    pass
        
        if sys_diag == True:
            try:
                if diagdict["seid"] != None:
                    me_dev_info['SEID'] = diagdict["seid"]
            except:
                pass

        #i = 0
        for key, value in me_dev_info.items():
             #if i < 9:
             #    group = 'Hardware'
             #else:
             #    group = 'Software'
             #i += 1 
            if key in ['Device Name', 'Device', 'Model Number', 'MAC (WiFi Address)', 'MAC (Bluetooth Address)', 'Unique Identifier', 'Unique Chip ID', 'Serial Number', 'Disk Capacity', 'SEID']:
                group = 'Hardware'
            elif key in ['Software', 'Buildnumber', 'Time Zone', 'Apple-ID']:
                group = 'Software'
            elif key in ['Last Number', 'ICCID', 'IMSI', 'MCC', 'MNC']:
                group = 'SIM'
            ET.SubElement(metadata_device_info, 'item', {
            'id': str(uuid.uuid4()),
            'name': key,
            'group': group,
            'sourceExtraction': '0'
            }).text = value


        afc_id = str(uuid.uuid4())
        appl_id = str(uuid.uuid4())
        diag_id = str(uuid.uuid4())
        
        file_id_list = []
        gps_list = []
        gps_file_id_list = []
        gps_file_index = []

        tagged_files = ET.SubElement(project, 'taggedFiles')
        findex = 0
        for file_info in filedict:
            id = str(uuid.uuid4())
            file_id_list.append(id)
            file_elem = ET.SubElement(tagged_files, 'file', {
                'fs': 'AFC_Media',
                'fsid': afc_id,
                'path': filedict[file_info]['metadata']['Local Path'].replace("files/AFC_Media/", ""),
                'size': filedict[file_info]['size'],
                'id': id,
                'extractionId': "0",
                'embedded': "false",
                'isrelated': "False"
            })
            if sys_diag == True:
                if latest_file in filedict[file_info]['metadata']['Local Path']:
                    diagsize = filedict[file_info]['size']
            access_info = ET.SubElement(file_elem, 'accessInfo')
            for timestamp_name, timestamp_value in filedict[file_info]['accessInfo'].items():
                ET.SubElement(access_info, 'timestamp', {'name': timestamp_name, 'format': 'TimeStampKnown', 'formattedTimestamp': timestamp_value}).text = timestamp_value
            metadata_file = ET.SubElement(file_elem, 'metadata', {'section': 'File'})
            for item_name, item_value in filedict[file_info]['metadata'].items():
                ET.SubElement(metadata_file, 'item', {'name': item_name}).text = item_value
            metadata_metadata = ET.SubElement(file_elem, 'metadata', {'section': 'MetaData'})
            ET.SubElement(metadata_metadata, 'item', {'name': "File size"}).text = ""
            if "Exif" in filedict[file_info]:
                for item_name, item_value in filedict[file_info]["Exif"].items():
                    item_attributes = {'name': item_name}
                    if item_name in ["EXIFCaptureTime", "MetaDataPixelResolution", "EXIFCameraMaker", "EXIFCameraModel", "EXIFOrientation", "MetaDataLatitudeAndLongitude"]:
                        item_attributes['group'] = "File Metadata"
                    else:
                        item_attributes['group'] = "EXIF"
                    ET.SubElement(metadata_metadata, 'item', item_attributes).text = str(item_value)
            if "GPS" in filedict[file_info]:
                gps_list.append(filedict[file_info])
                gps_file_id_list.append(id)
                gps_file_index.append(findex)
            findex += 1

        textfiles = [".txt", ".doc", ".docx", ".odt"]
        configfiles = [".plist", ".xml", ".config"]
        apppath = os.path.join("Report", "files", "Applications")
        for root, dirs, files in os.walk(apppath):
            for filename in files:
                entry = os.path.join(root, filename)
                if pathlib.Path(entry).is_file():
                    rep_path = str(pathlib.Path(entry).as_posix()).replace("Report/", "")
                    id = str(uuid.uuid4())
                    file_id_list.append(id)
                    file_elem = ET.SubElement(tagged_files, 'file', {
                        'fs': 'Applications',
                        'fsid': appl_id,
                        'path': rep_path.replace("files/Applications/", ""),
                        'size': str(os.stat(entry).st_size),
                        'id': id,
                        'extractionId': "0",
                        'embedded': "false",
                        'isrelated': "False"
                    })
                    access_info = ET.SubElement(file_elem, 'accessInfo')
                    ET.SubElement(access_info, 'timestamp', {'name': "CreationTime"}).text = ""
                    ET.SubElement(access_info, 'timestamp', {'name': "ModifyTime"}).text = ""
                    ET.SubElement(access_info, 'timestamp', {'name': "AccessTime"}).text = ""
                    metadata_file = ET.SubElement(file_elem, 'metadata', {'section': 'File'})
                    ET.SubElement(metadata_file, 'item', {'name': "Local Path"}).text = rep_path
                    ET.SubElement(metadata_file, 'item', {'name': "SHA256"}).text = str(hashlib.sha256(pathlib.Path(entry).read_bytes()).hexdigest())
                    ET.SubElement(metadata_file, 'item', {'name': "MD5"}).text = str(hashlib.md5(pathlib.Path(entry).read_bytes()).hexdigest())
                    if ".tar" in entry:
                        ET.SubElement(metadata_file, 'item', {'name': "Tags"}).text = "Archives"
                    elif any (x in entry.lower() for x in textfiles):
                        ET.SubElement(metadata_file, 'item', {'name': "Tags"}).text = "Text"
                    elif any(x in entry.lower() for x in configfiles):
                        ET.SubElement(metadata_file, 'item', {'name': "Tags"}).text = "Configuration"
                    else:
                        ET.SubElement(metadata_file, 'item', {'name': "Tags"}).text = "Uncategorized"
                    metadata_metadata = ET.SubElement(file_elem, 'metadata', {'section': 'MetaData'})
                    ET.SubElement(metadata_metadata, 'item', {'name': "File size"}).text = ""

        sysdiag_id = ""
        diagpath = os.path.join("Report", "files", "Diagnostics")
        for root, dirs, files in os.walk(diagpath):
            for filename in files:
                entry = os.path.join(root, filename)
                if pathlib.Path(entry).is_file():
                    rep_path = str(pathlib.Path(entry).as_posix()).replace("Report/", "")
                    id = str(uuid.uuid4())
                    file_id_list.append(id)
                    file_elem = ET.SubElement(tagged_files, 'file', {
                        'fs': 'Diagnostics',
                        'fsid': diag_id,
                        'path': rep_path.replace("files/Diagnostics/",""),
                        'size': str(os.stat(entry).st_size),
                        'id': id,
                        'extractionId': "0",
                        'embedded': "false",
                        'isrelated': "False"
                    })
                    access_info = ET.SubElement(file_elem, 'accessInfo')
                    ET.SubElement(access_info, 'timestamp', {'name': "CreationTime"}).text = ""
                    ET.SubElement(access_info, 'timestamp', {'name': "ModifyTime"}).text = ""
                    ET.SubElement(access_info, 'timestamp', {'name': "AccessTime"}).text = ""
                    metadata_file = ET.SubElement(file_elem, 'metadata', {'section': 'File'})
                    ET.SubElement(metadata_file, 'item', {'name': "Local Path"}).text = rep_path
                    ET.SubElement(metadata_file, 'item', {'name': "SHA256"}).text = str(hashlib.sha256(pathlib.Path(entry).read_bytes()).hexdigest())
                    ET.SubElement(metadata_file, 'item', {'name': "MD5"}).text = str(hashlib.md5(pathlib.Path(entry).read_bytes()).hexdigest())
                    if ".tar" in entry:
                        ET.SubElement(metadata_file, 'item', {'name': "Tags"}).text = "Archives"
                    elif any (x in entry.lower() for x in textfiles):
                        ET.SubElement(metadata_file, 'item', {'name': "Tags"}).text = "Text"
                    elif any(x in entry.lower() for x in configfiles):
                        ET.SubElement(metadata_file, 'item', {'name': "Tags"}).text = "Configuration"
                    else:
                        ET.SubElement(metadata_file, 'item', {'name': "Tags"}).text = "Uncategorized"
                    metadata_metadata = ET.SubElement(file_elem, 'metadata', {'section': 'MetaData'})
                    ET.SubElement(metadata_metadata, 'item', {'name': "File size"}).text = ""
                    if sys_diag == True:
                        if filename == latest_file:
                            sysdiag_id = id
                        else:
                            pass

        decoded_data = ET.SubElement(project, 'decodedData')

        model_types = [
            "UserAccount", "Contact", "Chat", "SMS", "MMS", "Email", "Call", 
            "CalendarEntry", "Note", "BluetoothDevice", "Cookie", "WebBookmark", "DeviceEvent",
            "VisitedPage", "SearchedItem", "WirelessNetwork", "Password", "RecognizedDevice", 
            "Notification", "CellTower", "Location", "Journey", "InstalledApplication"
        ]
        index = 0
        for model_type in model_types:
            model_type_elem = ET.SubElement(decoded_data, 'modelType', {'type': model_type})
            if model_type == "Location":
                if gps_list != []:
                    for file_info in gps_list:
                        gps_id = str(uuid.uuid4())
                        model_elem = ET.SubElement(model_type_elem, 'model', {
                            'type': 'Location', 
                            'id': gps_id,
                            'deleted_state': 'Intact',
                            'decoding_confidence': 'High',
                            'isrelated': 'False',
                            'source_index': '0',
                            'extractionId': '0'
                        })
                        model_field = ET.SubElement(model_elem, 'modelField', {
                            'name': 'Position',
                            'type': 'Coordinate'
                        })
                        coord_model = ET.SubElement(model_field, 'model', {
                            'type': 'Coordinate',
                            'id': str(uuid.uuid4()),
                            'deleted_state': 'Intact',
                            'decoding_confidence': 'High',
                            'isrelated': 'False',
                            'source_index': '0',
                            'extractionId': '0'
                        })
                        long_field = ET.SubElement(coord_model, 'field', {
                            'name': 'Longitude',
                            'type': 'Double'
                        })
                        ET.SubElement(long_field, 'value', {'type': 'Double'}).text = str(file_info["GPS"]["Longitude"])
                        lat_field = ET.SubElement(coord_model, 'field', {
                            'name': 'Latitude',
                            'type': 'Double'
                        })
                        ET.SubElement(lat_field, 'value', {'type': 'Double'}).text = str(file_info["GPS"]["Latitude"])
                        elev_field = ET.SubElement(coord_model, 'field', {
                            'name': 'Elevation',
                            'type': 'Double'
                        })
                        ET.SubElement(elev_field, 'value', {'type': 'Double'}).text = str(file_info["GPS"]["Elevation"])
                        try:
                            timestamp_field = ET.SubElement(model_elem, 'field', {'name': 'TimeStamp', 'type': 'TimeStamp'})
                            ET.SubElement(timestamp_field, 'value', {'type': 'TimeStamp'}).text = str(file_info["Exif"]["ExifEnumDateTimeOriginal"].replace(".","/").replace("(", " ").replace(")",""))
                        except:
                            pass
                        name_field = ET.SubElement(model_elem, 'field', {'name': 'Name', 'type': 'String'})               
                        ET.SubElement(name_field, 'value', {'type': 'String'}).text = str(os.path.basename(file_info["metadata"]["Local Path"]))
                        description_field = ET.SubElement(model_elem, 'field', {'name': 'Description', 'type': 'String'})
                        ET.SubElement(description_field, 'empty')
                        type_field = ET.SubElement(model_elem, 'field', {'name': 'Type', 'type': 'String'})
                        ET.SubElement(type_field, 'value', {'type': 'String'}).text = 'IMAGE'
                        precision_field = ET.SubElement(model_elem, 'field', {'name': 'Precision', 'type': 'String'})
                        ET.SubElement(precision_field, 'value', {'type': 'Double'})
                        confidence_field = ET.SubElement(model_elem, 'field', {'name': 'Confidence', 'type': 'String'})
                        ET.SubElement(confidence_field, 'empty')
                        category_field = ET.SubElement(model_elem, 'field', {'name': 'Category', 'type': 'String'})
                        ET.SubElement(category_field, 'value', {'type': 'String'}).text = 'Fotos'
                        origin_field = ET.SubElement(model_elem, 'field', {'name': 'Origin', 'type': 'LocationOrigin'})
                        ET.SubElement(origin_field, 'value', {'type': 'LocationOrigin'}).text = 'Unknown'
                        jump_targets = ET.SubElement(model_elem, 'jumptargets', {'name': ''})
                        ET.SubElement(jump_targets, 'targetid', {'ismodel': 'false'}).text = str(gps_file_id_list[index])
                        tagged_files = project.find('taggedFiles') 
                        file_elem = tagged_files[gps_file_index[index]]
                        jump_targets_element = ET.SubElement(file_elem, 'jumptargets', {'name': ''})
                        ET.SubElement(jump_targets_element, 'targetid', {'ismodel': 'true'}).text = gps_id
                        index += 1

            if model_type == "RecognizedDevice":
                if sys_diag == True:
                    try:
                        for device in diagdict["iclouddev"]:
                            model_elem = ET.SubElement(model_type_elem, 'model', {
                                'type': 'RecognizedDevice', 
                                'id': str(uuid.uuid4()),
                                'deleted_state': 'Intact',
                                'decoding_confidence': 'High',
                                'isrelated': 'False',
                                'source_index': '0',
                                'extractionId': '0'
                            })
                            source_field = ET.SubElement(model_elem, 'field', {'name': 'Source', 'type': 'String'})
                            ET.SubElement(source_field, 'value', {'type': 'String'}).text = "iCloud Keychain"
                            name_field = ET.SubElement(model_elem, 'field', {'name': 'Name', 'type': 'String'})
                            ET.SubElement(name_field, 'value', {'type': 'String'}).text = device[1]
                            type_field = ET.SubElement(model_elem, 'field', {'name': 'DeviceType', 'type': 'String'})
                            ET.SubElement(type_field, 'value', {'type': 'String'}).text = device[0]
                            multi_model_field = ET.SubElement(model_elem, 'multiModelField', {'name': 'DeviceIdentifiers', 'type': 'KeyValueModel'})
                            inner_model = ET.SubElement(multi_model_field, 'model', {
                                'type': 'KeyValueModel',
                                'id': str(uuid.uuid4()),
                                'deleted_state': 'Intact',
                                'decoding_confidence': 'High',
                                'isrelated': 'False',
                                'source_index': '0',
                                'extractionId': '0'
                            })
                            key_field = ET.SubElement(inner_model, 'field', {'name': 'Key', 'type': 'String'})
                            ET.SubElement(key_field, 'value', {'type': 'String'}).text = 'OS Build:'
                            value_field = ET.SubElement(inner_model, 'field', {'name': 'Value', 'type': 'String'})
                            ET.SubElement(value_field, 'value', {'type': 'String'}).text = device[2]
                            serial_field = ET.SubElement(model_elem, 'field', {'name': 'SerialNumber', 'type': 'String'})
                            ET.SubElement(serial_field, 'value', {'type': 'String'}).text = device[3]
                            jumptargets = ET.SubElement(model_elem, 'jumptargets', {'name': ''})
                            ET.SubElement(jumptargets, 'targetid', {'ismodel': 'true'}).text = sysdiag_id
                    except:
                        pass

            if model_type == "WirelessNetwork":
                if sys_diag == True:
                    try:
                        for network in diagdict["known_wifi"]:
                            model_elem = ET.SubElement(model_type_elem, 'model', {
                                'type': 'WirelessNetwork', 
                                'id': str(uuid.uuid4()),
                                'deleted_state': 'Intact',
                                'decoding_confidence': 'High',
                                'isrelated': 'False',
                                'source_index': '0',
                                'extractionId': '0'
                            })
                            source_field = ET.SubElement(model_elem, 'field', {'name': 'Source', 'type': 'String'})
                            ET.SubElement(source_field, 'value', {'type': 'String'}).text = network[6]
                            bssid_field = ET.SubElement(model_elem, 'field', {'name': 'BSSId', 'type': 'String'})
                            ET.SubElement(bssid_field, 'value', {'type': 'String'}).text = network[3]
                            ssid_field = ET.SubElement(model_elem, 'field', {'name': 'SSId', 'type': 'String'})
                            ET.SubElement(ssid_field, 'value', {'type': 'String'}).text = network[4]
                            sec_field = ET.SubElement(model_elem, 'field', {'name': 'SecurityMode', 'type': 'String'})
                            ET.SubElement(sec_field, 'value', {'type': 'String'}).text = network[5]
                            lastcon_field = ET.SubElement(model_elem, 'field', {'name': 'LastConnection', 'type': 'TimeStamp'})
                            ET.SubElement(lastcon_field, 'value', {'type': 'TimeStamp', 'format': 'TimeStampKnown', 'formattedTimestamp':  network[0]}).text = network[0]
                            timestamp_field = ET.SubElement(model_elem, 'field', {'name': 'TimeStamp', 'type': 'TimeStamp'})
                            ET.SubElement(timestamp_field, 'value', {'type': 'TimeStamp', 'format': 'TimeStampKnown', 'formattedTimestamp':  network[1]}).text = network[1]
                            endtime_field = ET.SubElement(model_elem, 'field', {'name': 'EndTime', 'type': 'TimeStamp'})
                            ET.SubElement(endtime_field, 'value', {'type': 'TimeStamp', 'format': 'TimeStampKnown', 'formattedTimestamp':  network[2]}).text = network[2]
                            jumptargets = ET.SubElement(model_elem, 'jumptargets', {'name': ''})
                            ET.SubElement(jumptargets, 'targetid', {'ismodel': 'true'}).text = sysdiag_id
                    except:
                        pass
        
            if model_type == "DeviceEvent":
                if sys_diag == True:
                    try:
                        for event in diagdict["device_events"]:
                            model_elem = ET.SubElement(model_type_elem, 'model', {
                                'type': 'DeviceEvent', 
                                'id': str(uuid.uuid4()),
                                'deleted_state': 'Intact',
                                'decoding_confidence': 'High',
                                'isrelated': 'False',
                                'source_index': '0',
                                'extractionId': '0'
                            })
                            map_field = ET.SubElement(model_elem, 'field', {'name': 'UserMapping', 'type': 'DecodingSourceOptions'})
                            ET.SubElement(map_field, 'value', {'type': 'DecodingSourceOptions'}).text = "Decoding"
                            source_field = ET.SubElement(model_elem, 'field', {'name': 'Source', 'type': 'String'})
                            ET.SubElement(source_field, 'value', {'type': 'String'}).text = "Power events"
                            timestamp_field = ET.SubElement(model_elem, 'field', {'name': 'StartTime', 'type': 'TimeStamp'})
                            ET.SubElement(timestamp_field, 'value', {'type': 'TimeStamp', 'format': 'TimeStampKnown', 'formattedTimestamp':  event[1]}).text = event[1]
                            type_field = ET.SubElement(model_elem, 'field', {'name': 'EventType', 'type': 'DeviceEventTypes'})
                            ET.SubElement(type_field, 'value', {'type': 'DeviceEventTypes'}).text = "PowerEvent"
                            value_field = ET.SubElement(model_elem, 'field', {'name': 'Value', 'type': 'String'})
                            ET.SubElement(value_field, 'value', {'type': 'String'}).text = "Power on"
                            multi_model_field = ET.SubElement(model_elem, 'multiModelField', {'name': 'Additional_Info', 'type': 'KeyValueModel'})
                            inner_model = ET.SubElement(multi_model_field, 'model', {
                                'type': 'KeyValueModel',
                                'id': str(uuid.uuid4()),
                                'deleted_state': 'Intact',
                                'decoding_confidence': 'High',
                                'isrelated': 'False',
                                'source_index': '0',
                                'extractionId': '0'
                            })
                            key_field = ET.SubElement(inner_model, 'field', {'name': 'Key', 'type': 'String'})
                            ET.SubElement(key_field, 'value', {'type': 'String'}).text = 'File:'
                            value_field = ET.SubElement(inner_model, 'field', {'name': 'Value', 'type': 'String'})
                            ET.SubElement(value_field, 'value', {'type': 'String'}).text = event[2]
                            jumptargets = ET.SubElement(model_elem, 'jumptargets', {'name': ''})
                            ET.SubElement(jumptargets, 'targetid', {'ismodel': 'true'}).text = sysdiag_id
                    except Exception as e:
                        print(e)
                        pass

        installed_apps_type = ET.SubElement(decoded_data, 'modelType', {'type': 'InstalledApplication'})  

        for app in app_report_list:
            model_elem = ET.SubElement(installed_apps_type, 'model', {
                'type': 'InstalledApplication',
                'id': app['id'],
                'deleted_state': 'Intact',
                'decoding_confidence': 'High',
                'isrelated': 'False',
                'source_index': '0',
                'extractionId': '0'
            })

            name_field = ET.SubElement(model_elem, 'field', {'name': 'Name', 'type': 'String'})
            ET.SubElement(name_field, 'value', {'type': 'String'}).text = app['name']
            version_field = ET.SubElement(model_elem, 'field', {'name': 'Version', 'type': 'String'})
            ET.SubElement(version_field, 'value', {'type': 'String'}).text = app['version']
            identifier_field = ET.SubElement(model_elem, 'field', {'name': 'Identifier', 'type': 'String'})
            ET.SubElement(identifier_field, 'value', {'type': 'String'}).text = app['identifier']

            if app['identifier'] in purchasedict.keys():
                purchase_date_field = ET.SubElement(model_elem, 'field', {'name': 'PurchaseDate', 'type': 'TimeStamp'})
                ET.SubElement(purchase_date_field, 'value', {'type': 'TimeStamp', 'format': 'TimeStampKnown', 'formattedTimestamp':  purchasedict[app['identifier']]}).text = purchasedict[app['identifier']]

            install_date_field = ET.SubElement(model_elem, 'field', {'name': 'InstallDate', 'type': 'TimeStamp'})
            ET.SubElement(install_date_field, 'empty')
            last_modified_field = ET.SubElement(model_elem, 'field', {'name': 'LastModified', 'type': 'TimeStamp'})
            ET.SubElement(last_modified_field, 'empty')

        extra_infos = ET.SubElement(project, 'extraInfos')

        for node_id in file_id_list:
            extra_info = ET.SubElement(extra_infos, 'extraInfo', {'type': 'node', 'id': node_id})
            source_info = ET.SubElement(extra_info, 'sourceInfo')
            if sys_diag == True and node_id == sysdiag_id:
                ET.SubElement(source_info, 'nodeInfo', {'id': node_id, 'name': latest_file, 'size': diagsize,'tableName': '', 'offset': ''})
            else:
                ET.SubElement(source_info, 'nodeInfo', {'id': node_id, 'tableName': '', 'offset': ''})

        rough_string = ET.tostring(project, 'utf-8', method='xml')
        reparsed = minidom.parseString(rough_string)
        xml_str = reparsed.toprettyxml(indent="  ", encoding="ascii")
        with open(os.path.join("Report", "report.xml"), "wb") as f:
            f.write(xml_str)

        path="Report"
        #arcname = f"{udid}_Report"
        #shutil.make_archive(arcname, 'zip', path)
        #p = pathlib.Path(f"{arcname}.zip")
        #try: p.rename(p.with_suffix('.ufdr'))
        #except: pass

        len_path = len(os.path.abspath(path)) + 1
        with zipfile.ZipFile(f'{dev_name}_{datetime.now().strftime("%Y_%m_%d")}_report.ufdr', 'w') as zip:
            for root, dirs, files in os.walk(path):
                for file in files:
                    try:
                        filepath = os.path.abspath(os.path.join(root, file))
                        relative_path = filepath[len_path:]
                        with open(filepath, 'rb') as f:
                            zipinfo = zipfile.ZipInfo(filepath)
                            zip.write(filepath, relative_path)
                    except:
                        log(f"Error zipping File: {file}")
        shutil.rmtree(path)
        log("Created UFDR Report")
        change.set(1)

    def show_pdf_report(self):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Generate PDF Report", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Provide the case information:", width=585, height=30, font=self.stfont, anchor="w", justify="left")
        self.change = ctk.IntVar(self, 0)
        self.text.pack(anchor="center", pady=25)
        
        self.casebox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="case number")
        self.casebox.pack(pady=5, padx=30)
        self.namebox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="case name")
        self.namebox.pack(pady=5, padx=30)
        self.evidbox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="evidence number")
        self.evidbox.pack(pady=5, padx=30)  
        self.exambox = ctk.CTkEntry(self.dynamic_frame, width=360, height=20, corner_radius=0, placeholder_text="examiner")
        self.exambox.pack(pady=5, padx=30) 
        self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.change.set(1))
        self.okbutton.pack(pady=30, padx=100)
        global case_number
        global case_name
        global evidence_number
        global examiner
        if case_number != "":
                self.casebox.insert(0, string=case_number)
        else:
            pass
        if case_name != "":
                self.namebox.insert(0, string=case_name)
        else:
            pass
        if evidence_number != "":
                self.evidbox.insert(0, string=evidence_number)
        else:
            pass
        if examiner != "":
                self.exambox.insert(0, string=examiner)
        else:
            pass
        self.wait_variable(self.change)
        self.casebox.pack_forget()
        self.namebox.pack_forget()
        self.evidbox.pack_forget()
        self.exambox.pack_forget()
        self.okbutton.pack_forget()
        self.change.set(0)
        case_number = self.casebox.get()
        case_name = self.namebox.get()
        evidence_number = self.evidbox.get()
        examiner = self.exambox.get()
        self.pdf_report(case_number, case_name, evidence_number, examiner)
        self.text.configure(text="PDF creation complete!", height=60)
        if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("ReportMenu")).pack(pady=40))
        else:
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("iReportMenu")).pack(pady=40))

#PDF Device Report with pdfme
    def pdf_report(self, case_number="", case_name="", evidence_number="", examiner="", pdf_type="default", shot="none", sha256="none", shot_png="none", app_name=None, chat_name=None, w=None, h=None):
        hobude = ["1,1","1,2","2,1","3,1","3,2","3,3","4,1","5,1","5,2","5,3","5,4","6,1","6,2","7,1","7,2","8,1","8,2","8,4","9,1","9,2","9,3","9,4","10,1","10,2","10,4","10,5","12,8","14,6"]   
        u_grey = [0.970, 0.970, 0.970]
        #background_color = tuple(int(c * 255) for c in u_grey)
        font_size = 64
        font_path = os.path.join(os.path.dirname(__file__),"assets", "report", "texgyreheros-regular.otf")
        font = ImageFont.truetype(font_path, font_size)
        dummy_image = Image.new("RGB", (1, 1))
        draw = ImageDraw.Draw(dummy_image)
        text_width = 2400
        image = Image.new("RGB", (int(text_width), font_size+8), 'white')
        draw = ImageDraw.Draw(image)
        draw.text((0,-16),text=name, font=font, fill="black")
        image_stream = BytesIO()
        image.save(image_stream, format="JPEG", quality=95)
        image_stream.seek(0)
        if h == 426:
            lr_width = (1.4 * (185/w))    
        else:
            lr_width = 0.5
        if app_name != None:
            app_name = f'{app_name} (Named by examiner)'
        if chat_name != None:
            chat_name = f'{chat_name} (Named by examiner)'

        with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as temp_file:
            temp_file.write(image_stream.getvalue())
            temp_image_name = temp_file.name


        global number
        try: 
            number = lockdown.get_value(key="PhoneNumber")
            if number == None:
                number = ""
        except: number = ""
        global all
        try: 
            all = lockdown.all_values.get("CarrierBundleInfoArray")
            if all == None:
                all = ""
        except: 
            all = ""
        try: tele = lockdown.get_value("", "TelephonyCapability")
        except: tele = False
        if int(dversion.split(".")[0]) >= 17:
            try:
                springboard_rep = str(SpringBoardServicesService(lockdown).get_icon_state())
            except:
                springboard_rep = app_id_list
        else:
            springboard_rep = app_id_list
        
        if d_class == "Watch":
            d_image = os.path.join(os.path.dirname(__file__), "assets" , "report", "watch.jpg")
        elif d_class == "AppleTV":
            d_image = os.path.join(os.path.dirname(__file__), "assets" , "report", "tv.jpg")
        elif d_class == "iPad":
            d_image = os.path.join(os.path.dirname(__file__), "assets" , "report", "ipad.jpg")
        elif d_class == "iPod":
            d_image = os.path.join(os.path.dirname(__file__), "assets" , "report", "ipod.jpg")
        elif d_class == "AudioAccessory":
            d_image = os.path.join(os.path.dirname(__file__), "assets" , "report", "homepod.jpg")
        else:
            if product in ["iPhone" + nr for nr in hobude]:
                d_image = os.path.join(os.path.dirname(__file__), "assets" , "report", "iphone2.jpg")
            else:
                d_image = os.path.join(os.path.dirname(__file__), "assets" , "report", "iphone.jpg")     
        if pdf_type == "screenshot":
            document = {
                "style": {"margin_bottom": 15, "text_align": "j", "page_size": "a4", "margin": [52, 70]},
                "formats": {
                    "url": {"c": "blue", "u": 1}, "title": {"b": 1, "s": 13}},
                "running_sections": {
                    "header": {
                        "x": "left", "y": 20, "height": "top", "style": {"text_align": "r"}, "content": [{".b": "Device Report - Generated by UFADE"}]},
                    "footer": {
                        "x": "left", "y": 800, "height": "bottom", "style": {"text_align": "c"}, "content": [{".": ["Page ", {"var": "$page"}]}]}
                },
                "sections": [
                    {
                        "style": {"page_numbering_style": "arabic"},
                        "running_sections": ["footer"],
                        "content": [
                            {
                                "widths": [0.8, 0.1, 8.5],
                                "style": {"s": 10, "border_color": "white",},
                                "table": [

                                    [
                                        {"image": os.path.join(os.path.dirname(__file__), "assets" , "report", "report_u.jpg")}, None,
                                        {".": [{".b;s:18": "UFADE Screenshot Report" + "\n"}, f"Created with UFADE {u_version}"]}
                                    ]
                                ]
                            },
                            {".": "Device:", "style": "title", "label": "title2", "outline": {}},
                            {
                                "widths": [1.2, 2.5, 1.8, 2.5],
                                "style": {"s": 10, "border_color": "lightgrey"},
                                "table": [
                                    [{".": [{".b": "Dev-Name:"}]}, {"colspan": 3, "image": temp_image_name}, None, None],
                                    [{"style": {"border_color": "white", "cell_fill": u_grey}, ".": [{".b": "Model-Nr:"}]}, {"colspan": 3, "style": {"cell_fill": u_grey}, ".": [{".": dev_name}]}, None, None],
                                    [{".": [{".b": "UDID:"}]}, {"colspan": 3, ".": [{".": udid}]}, None, None],
                                ]
                            },
                            {".": "Screenshot:", "style": "title", "label": "title2", "outline": {}},
                            {
                                "widths": [1.2, 2.5, 1.8, 2.5],
                                "style": {"s": 10, "border_color": "lightgrey"},
                                "table": [
                                    [{".": [{".b": "Name:"}]}, {"colspan": 3, ".": [{".": shot}]}, None, None],
                                    [{"style": {"border_color": "white", "cell_fill": u_grey}, ".": [{".b": "SHA256:"}]}, {"colspan": 3, "style": {"cell_fill": u_grey}, ".": [{".": sha256}]}, None, None],
                                ]
                            },
                            {
                                "widths": [1.2, 2.5, 1.8, 2.5],
                                "style": {"s": 10, "border_color": "lightgrey"},
                                "table": [
                                    [{".": [{".b": "App:"}]}, {"colspan": 3, ".": [{".": app_name}]}, None, None],
                                    [{"style": {"border_color": "white", "cell_fill": u_grey}, ".": [{".b": "Chat:"}]}, {"colspan": 3, "style": {"cell_fill": u_grey}, ".": [{".": chat_name}]}, None, None],
                                ]
                            } if app_name is not None else "",
                            {
                                "widths": [lr_width, 2, lr_width],
                                "style": {"s": 10, "border_color": "white"},
                                "table": [
                                    [None, {"image": shot_png, "min_height":300}, None],
                                ]

                            },
                            ]
                            },
                            #{".": "", "style": "title", "label": "title0", "outline": {}},
            ]
        }
        else:

            apps_content = []
            if len(apps) > 0:
                for i, d_app in enumerate(app_id_list):
                    row_bg = u_grey if (i % 2) != 0 else "white"
                    mini_table = {
                        "keepTogether": True, 
                        "widths": [2.1, 3.7, 1.7, 0.7],
                        "style": {
                            "s": 9,
                            "border_color": "lightgrey", 
                            "margin_bottom": 0 
                        },
                        "table": [
                            [
                                {"style": {"cell_fill": row_bg}, ".": apps.get(d_app)['CFBundleDisplayName'].encode('latin-1', errors='ignore').decode('latin-1')[:22]},
                                {"style": {"cell_fill": row_bg}, ".": d_app},
                                {"style": {"cell_fill": row_bg}, ".": apps.get(d_app)['CFBundleVersion']},
                                {"style": {"cell_fill": row_bg}, ".": "visible" if d_app in springboard_rep else "absent"}
                            ]
                        ]
                    }
                    apps_content.append(mini_table)

            document = {
                "style": {"margin_bottom": 15, "text_align": "j", "page_size": "a4", "margin": [52, 70]},
                "formats": {
                    "url": {"c": "blue", "u": 1}, "title": {"b": 1, "s": 13}},
                "running_sections": {
                    "header": {
                        "x": "left", "y": 20, "height": "top", "style": {"text_align": "r"}, "content": [{".b": "Device Report - Generated by UFADE"}]},
                    "footer": {
                        "x": "left", "y": 800, "height": "bottom", "style": {"text_align": "c"}, "content": [{".": ["Page ", {"var": "$page"}]}]}
                },
                "sections": [
                    {
                        "style": {"page_numbering_style": "arabic"},
                        "running_sections": ["footer"],
                        "content": [

                            {
                                "widths": [0.8, 0.1, 8.5],
                                "style": {"s": 10, "border_color": "white",},
                                "table": [
                                    [
                                        {"image": os.path.join(os.path.dirname(__file__), "assets" , "report", "report_u.jpg")}, None,
                                        {".": [{".b;s:18": "UFADE Device Report" + "\n"}, f"Created with UFADE {u_version}"]}
                                    ]
                                ]
                            },
                            {".": ""},{".": ""},
                            {".": "Case Information:", "style": "title", "label": "title1", "outline": {}},
                            {
                                "widths": [1.8, 0.5, 2.5, 5],
                                "style": {"s": 10, "border_color": "white",},
                                "table": [
                                    [{"rowspan": 4, "image": d_image}, None, {".": [{".b": "Case Number:"}]}, {".": [{".": case_number}]}],
                                    [None, None, {".": [{".b": "Case Name:"}]}, {".": [{".": case_name}]}],
                                    [None, None, {".": [{".b": "Evidence Number:"}]}, {".": [{".": evidence_number}]}],
                                    [None, None, {".": [{".b": "Examiner:"}]}, {".": [{".": examiner}]}]
                                ]
                            },
                            {".": "",},
                            {".": "Device Information:", "style": "title", "label": "title2", "outline": {}},
                            {
                                "widths": [1.2, 2.5, 1.2, 3.1],
                                "style": {"s": 10, "border_color": "lightgrey"},
                                "table": [
                                    [{".": [{".b": "Dev-Name:"}]}, {"colspan": 3, "image": temp_image_name}, None, None],
                                    [{"style": {"border_color": "white", "cell_fill": u_grey}, ".": [{".b": "Model-Nr:"}]}, {"colspan": 3, "style": {"cell_fill": u_grey}, ".": [{".": dev_name}]}, None, None],
                                    [{".": [{".b": "UDID:"}]}, {"colspan": 3, ".": [{".": udid}]}, None, None],
                                    [{"style": {"cell_fill": u_grey}, ".": [{".b": "Hardware:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": hardware_mnr}]}, { "style": {"cell_fill": u_grey}, ".": [{".b": "WiFi MAC:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": w_mac}]}],
                                    [{".": [{".b": "Product:"}]}, {".": [{".": product}]}, {".": [{".b": "BT MAC:"}]}, {".": [{".": b_mac}]}],
                                    [{"style": {"cell_fill": u_grey}, ".": [{".b": "Software:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": dversion}]}, {"style": {"cell_fill": u_grey}, ".": [{".b": "Capacity:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": f"{disk} GB"}]}],
                                    [{".": [{".b": "Build Nr:"}]}, {".": [{".": build}]}, {".": [{".b": "Free Space:"}]}, {".": [{".": f"{free} GB"}]}],
                                    [{"style": {"cell_fill": u_grey}, ".": [{".b": "Language:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": language}]}, {"style": {"cell_fill": u_grey}, ".": [{".b": "ECID:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": ecid}]}],
                                    [{".": [{".b": "Serialnr:"}]}, {".": [{".": snr}]}, {".": [{".b": "IMEI:"}]}, {".": [{".": imei}]}],
                                    [{"style": {"cell_fill": u_grey}, ".": [{".b": "MLB-snr:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": mlbsnr}]}, {"style": {"cell_fill": u_grey}, ".": [{".b": "IMEI 2:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": imei2}]}]
                                ]

                            },
                            {".": "",},
                            {
                                ".": "Telephony:", "style": "title", "label": "title1", "outline": {}
                            },
                            #{"image": "report_u.jpg"},
                            {
                                "widths": [2.5, 7.5],
                                "style": {"s": 10, "border_color": "lightgrey"},
                                "table": [[{".": [{".b": "Cellular:"}]}, {".": [{".": "yes" if tele == True else "no"}]},],
                                        [{".": [{".b": "Last Number:"}]}, {".": [{".": number if number != "" else "None"}]},]]
                            },
                            {".": ""},
                            {
                                ".": "Companion Device:", "style": "title", "label": "title1", "outline": {}
                            },
                            {
                                "widths": [2.5, 7.5],
                                "style": {"s": 10, "border_color": "lightgrey"},
                                "table": [[{".": [{".b": "Companion-UDID:"}]}, {".": [{".": comp if comp != [] else "None"}]},]]
                            },
                            ["For iOS devices, the companion device is usually an Apple Watch."],
                            
                            {".": "",},
                
                            {
                                ".": "SIM Info:", "style": "title", "label": "title1",
                                "outline": {}
                            },
                            *[
                                {
                                "widths": [1.5, 2.7, 1.5, 2.5],
                                "style": {"s": 10, "border_color": "lightgrey"},
                                "table": [
                                    [{".": [{".b": "ICCID:"}]}, {"colspan": 3, ".": [{".": entry["IntegratedCircuitCardIdentity"]}]}, None, None],
                                    [{"style": {"cell_fill": u_grey}, ".": [{".b": "IMSI:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": entry["InternationalMobileSubscriberIdentity"]}]}, { "style": {"cell_fill": u_grey}, ".": [{".b": "MCC:"}]}, {"style": {"cell_fill": u_grey}, ".": [{".": entry["MCC"]}]}],
                                    [{".": [{".b": "MNC:"}]}, {".": [{".": entry["MNC"]}]}, {".": [{".b": "Slot:"}]}, {".": entry["Slot"]}] 
                                    ]}               
                            for entry in all if all != ""],
                            ["None" if all == "" else ""],

                            {".": "",},
                
                            {
                                ".": "Applications:", "style": "title", "label": "title1", "outline": {}
                            },
                            
                            {
                                "widths": [2.1, 3.7, 1.7, 0.7],
                                "style": {"s": 9, "border_color": "white", "margin_bottom": 2},
                                "table": [
                                    [{".": [{".b":"Name"}]},{".": [{".b":"Bundle Identifier"}]},{".": [{".b":"Version"}]},{".":[{".b":"visible"}]}]
                                ]
                            },

                            *apps_content,              

                            {".": "", "style": "title", "label": "title0", "outline": {}},
                        ] 

                    },
                ]
            }
        if pdf_type == "screenshot":
            screen_pdf_path = os.path.splitext(shot_png)[0]+'.pdf'
            with open(screen_pdf_path, 'wb') as f:
                build_pdf(document, f)
        else:
            with open(f'Report_{udid}.pdf', 'wb') as f:
                build_pdf(document, f)

#AMFI Developer:
    def amfi_developer(self, text):
        try:
            AmfiService(lockdown).enable_developer_mode(enable_post_restart=True)
        except exceptions.DeviceHasPasscodeSetError:
            AmfiService(lockdown).reveal_developer_mode_option_in_ui()
            text.configure(text="The developer mode has to be activated manually.\n\nNavigate to: Settings > Privacy & Security > Developer Mode (bottom) \n\nand activate the new option. Wait for the device to reboot.\nUnlock it and confirm the activation of the developer mode.\nAfter this, press \"OK\".")

# Try to mount a suitable developerdiskimage
    def mount_developer(self, change, text):
        global developer
        global lockdown
        if d_class == "Watch":
            d_images = {2:[0,1,2], 3:[0,1,2], 4:[0,1,2,3], 5:[0,1,2], 6:[0,1,2], 7:[0,1,2,3,4],
                        8:[0,3,5,7], 9:[0,1,4]}
        else:
            d_images = {4:[2,3], 5:[0,1], 6:[0,1], 7:[0,1], 8:[0,1,2,3,4], 9:[0,1,2,3],
                        10:[0,1,2,3], 11:[0,1,2,3,4], 12:[0,1,2,3,4], 13:[0,1,1.2,2,3,4,5,6,7],
                        14:[0,1,2,3,4,5,6,7,7.1,8], 15:[0,1,2,3,3.1,4,5,6,6.1,7],
                        16:[0,1,2,3,3.1,4,4.1,5,6,7]}
        try:
            if DeveloperDiskImageMounter(lockdown).copy_devices() != []:
                developer = True
                change.set(1)
                return("developer")
        except exceptions.MessageNotSupportedError:
            if d_class == "Watch":
                if int(dversion.split(".")[0]) < 8:
                    pass
                else:
                    text.configure(text="Something went wrong. Make sure the device is unlocked.")
                    change.set(1)
                    return("nope")
            else:  
                if int(dversion.split(".")[0]) < 15:
                    pass
                else:
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
                text.configure(text="The device has to be rebooted in order to activate the developer mode.\n\nDo you want to restart the device?")
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
                        #amfi_dev = threading.Thread(target=lambda: AmfiService(lockdown).enable_developer_mode(enable_post_restart=True))
                        amfi_dev = threading.Thread(target=lambda: self.amfi_developer(text))
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
        ddin = False
        if d_class == "Watch":
            if int(dversion.split(".")[0]) < 10:
                ddin = True
        else:
            if int(dversion.split(".")[0]) < 17:
                ddin = True
        print(ddin)
        
        if ddin == True:
            v = dversion.split(".")
            try: 
                self.after(100)
                text.configure(text=" ", anchor="nw", justify="left")
                text.update()
                self.after(1000)
                info = ("Looking for version " + dversion)
                text.configure(text=info)
                self.after(1000)
                if d_class == "Watch":
                    if not os.path.isdir(os.path.join(os.path.dirname(__file__),"ufade_developer", "Developer", "Watch", dversion)):
                        raise Exception("Version not found!") 
                else:
                    if not os.path.isdir(os.path.join(os.path.dirname(__file__),"ufade_developer", "Developer", dversion)):
                        raise Exception("Version not found!") 
                lockdown = create_using_usbmux()
                if d_class == "Watch":
                    DeveloperDiskImageMounter(lockdown).mount(image=os.path.join(os.path.dirname(__file__),"ufade_developer", "Developer", "Watch", dversion, "DeveloperDiskImage.dmg"), signature=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", "Watch", dversion, "DeveloperDiskImage.dmg.signature"))
                else:
                    DeveloperDiskImageMounter(lockdown).mount(image=os.path.join(os.path.dirname(__file__),"ufade_developer", "Developer", dversion, "DeveloperDiskImage.dmg"), signature=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", dversion, "DeveloperDiskImage.dmg.signature"))
                developer = True
                change.set(1)
                return("developer")   
            except:
                info = info + "\nVersion " + dversion + " not found"
                text.configure(text=info)
                self.after(1000)
                v_check = np.array(d_images[int(v[0])])
                v_diff = np.absolute(v_check - int(v[1]))
                index = v_diff.argmin()
                ver = str(v[0]) + "." + str(d_images[int(v[0])][index])
            finally:
                mounted = []
                try: mounted = DeveloperDiskImageMounter(lockdown).copy_devices()
                except: pass
                if int(v[0]) <= 13 or mounted == []:
                    self.after(1000)
                    info = info + "\nClosest version is " + ver
                    text.configure(text=info)
                    lockdown = create_using_usbmux()
                    self.after(1000)
                    try:
                        self.after(50)
                        if d_class == "Watch":
                            DeveloperDiskImageMounter(lockdown).mount(image=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", "Watch", ver, "DeveloperDiskImage.dmg"), signature=os.path.join(os.path.dirname(__file__),"ufade_developer", "Developer", "Watch", ver, "DeveloperDiskImage.dmg.signature"))
                        else:
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
                                if d_class == "Watch":
                                    DeveloperDiskImageMounter(lockdown).mount(image=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", "Watch", ver, "DeveloperDiskImage.dmg"), signature=os.path.join(os.path.dirname(__file__),"ufade_developer", "Developer", "Watch", ver, "DeveloperDiskImage.dmg.signature"))
                                else:
                                    DeveloperDiskImageMounter(lockdown).mount(image=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", ver, "DeveloperDiskImage.dmg"), signature=os.path.join(os.path.dirname(__file__),"ufade_developer", "Developer", ver, "DeveloperDiskImage.dmg.signature"))
                                info = info + "\nVersion: " + ver + " was used"
                                text.configure(text=info)
                                self.after(1000)
                                break
                            except:
                                pass
                        if int(v[0]) <= 13:
                            developer = True
                            change.set(1)
                            return("developer")
                        else:
                            pass
                        try: mounted = DeveloperDiskImageMounter(lockdown).copy_devices()
                        except: pass
                        if mounted == []:
                            text.configure(text="DeveloperDiskImage not loaded")
                            developer = False
                            change.set(1)
                            return("nope")
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
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Developer Options", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
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

        new_dev = False
        if d_class == "Watch":
            if int(dversion.split(".")[0]) >= 10:
                new_dev = True
        else:
            if int(dversion.split(".")[0]) >= 17:
                new_dev = True
        if new_dev == True:
            try:
                if lockdown.developer_mode_status == True:
                    pass
                else:
                    self.choose = ctk.BooleanVar(self, False)
                    self.text.configure(text="The device has to be rebooted in order to activate the developer mode.\n\nDo you want to restart the device?")
                    self.yesb = ctk.CTkButton(self.dynamic_frame, text="YES", font=self.stfont, command=lambda: self.choose.set(True))
                    self.yesb.pack(side="left", pady=(0,350), padx=140)
                    self.nob = ctk.CTkButton(self.dynamic_frame, text="NO", font=self.stfont, command=lambda: self.choose.set(False))
                    self.nob.pack(side="left", pady=(0,350))    
                    self.wait_variable(self.choose)  
                    if self.choose.get() == True:
                        self.yesb.pack_forget()
                        self.nob.pack_forget()
                        self.text.configure(text="Wait for the device to reboot.\nUnlock it and confirm the activation of the developer mode.\nAfter this, press \"OK\".")
                        try:
                            amfi_dev = threading.Thread(target=lambda: self.amfi_developer(self.text))
                            amfi_dev.start()
                            self.choose.set(False)
                            self.okbutton = ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.choose.set(True))
                            self.okbutton.pack()
                            self.wait_variable(self.choose)
                            self.okbutton.pack_forget()
                            self.after(50)
                            if lockdown.developer_mode_status != True:
                                self.text.configure(text="Uh-Oh, an error was raised.\nWait for the device to reboot and try again.")
                                self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
                                return
                            else:
                                pass
                        except:
                            self.text.configure(text="Uh-Oh, an error was raised. Please remove the PIN/PW and try again")
                            developer = False
                            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
                            return
                    else:
                        self.yesb.pack_forget()
                        self.nob.pack_forget()
                        developer = False
                        self.show_main_menu()
                        return
            except:
                pass
    
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

        if self.change.get() == 2:
            return

        if developer == True:
            try:
                new_dev == False
                if d_class == "Watch":
                    if int(dversion.split(".")[0]) >= 10:
                        lockdown = get_tunneld_devices()[0]
                        new_dev == True
                else:    
                    if int(dversion.split(".")[0]) >= 17:
                        lockdown = get_tunneld_devices()[0]
                        new_dev == True
                if new_dev == False:
                    lockdown = create_using_usbmux()
                dvt = DvtSecureSocketProxyService(lockdown)
                dvt.__enter__()
            except:
                if int(dversion.split(".")[0]) >= 17:
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
                if d_class == "Watch":
                    if int(dversion.split(".")[0]) >= 10:
                        new_dev = True
                else:
                    if int(dversion.split(".")[0]) >= 17:
                        new_dev = True
                if new_dev == True:
                    try:
                        lockdown = get_tunneld_devices()[0]
                    except:
                        try:
                            lockdown.connect()
                        except:
                            if platform.uname().system == 'Windows':
                                self.text.configure(text="Something went wrong. Try again.\nOn iOS 18 and up this is expected.\nPlease restart UFADE.")
                            else:
                                self.text.configure(text="Something went wrong. Try again.\nOn iOS 18 and up this is expected.")
                            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
                            return

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
            if getattr(sys, 'frozen', False):
                self.waitm = ctk.IntVar(self, 0)
                self.linux_17 = threading.Thread(target=lambda: self.linux_dev17(self.waitm))
                self.linux_17.start()
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
            else:
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
                    change.set(2)
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
            if getattr(sys, 'frozen', False):
                try:
                    print("try")
                    run(["osascript", "-e", f'do shell script \"{sys.executable} tunnel\" with administrator privileges'])
                except:
                    raise exceptions.AccessDeniedError()
            else:    
                run(["osascript", "-e", 'do shell script \"python3 -m pymobiledevice3 remote tunneld -d\" with administrator privileges'])
            change.set(1)
        except exceptions.AccessDeniedError:
            self.text.configure(text="Couldn't create a tunnel. Try again.\nYou have to run UFADE as administrator for this.")
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
            change.set(2)
            return
        except:
            self.text.configure(text="Couldn't create a tunnel. Try again.")
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
            change.set(2)
            return

    def linux_dev17(self, change):
        try:
            try:
                print("try")
                run(["pkexec", sys.executable, "tunnel"])
            except:
                raise exceptions.AccessDeniedError()     
            change.set(1)
        except exceptions.AccessDeniedError:
            self.text.configure(text="Couldn't create a tunnel. Try again.\nYou have to run UFADE as administrator for this.")
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
            change.set(2)
            return
        except:
            self.text.configure(text="Couldn't create a tunnel. Try again.")
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=self.show_main_menu).pack(pady=40))
            change.set(2)
            return

# Device screenshot
    def screen_device(self, dvt):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Take Screenshots", height=30, width=585, font=("standard",24), justify="left").pack(pady=10)
        self.shotframe = ctk.CTkFrame(self.dynamic_frame, width=400, corner_radius=0, fg_color="transparent")
        self.textframe = ctk.CTkFrame(self.dynamic_frame, width=200, corner_radius=0, fg_color="transparent")
        self.shotframe.pack(side="left", pady=20, padx=30, fill="y", expand=True)
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
        if d_class == "Watch":
            try:
                png = ScreenshotService(lockdown).take_screenshot()
            except:
                png = Screenshot(dvt).get_screenshot()
        else:
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
        filepath = os.path.join("screenshots", filename)
        hashpath = os.path.join("screenshots", hashname)
        with open(filepath, "wb") as file:
            file.write(png)
        with open(hashpath, "w") as hash_file:
            hash_file.write(hash_sha256)
        log(f"Created screenshot {filename} with hash {hash_sha256}")
        namefield.configure(text=f"Screenshot saved as:\n{filename}\nHash saved as:\n{hashname}")
        self.pdf_report(pdf_type="screenshot", shot=filename, sha256=hash_sha256, shot_png=filepath, w=wsize, h=hsize)

    def chat_shotloop(self, dvt):
        try: os.mkdir("screenshots")
        except: pass
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Chat Capture", height=30, width=585, font=("standard",24), justify="left").pack(pady=10)
        self.shotframe = ctk.CTkFrame(self.dynamic_frame, width=400, corner_radius=0, fg_color="transparent")
        self.textframe = ctk.CTkFrame(self.dynamic_frame, width=200, corner_radius=0, fg_color="transparent")
        self.shotframe.pack(side="left", pady=20, padx=30, fill="y", expand=True)
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
        abs_count = 0
        self.upbutton.configure(state="disabled")
        self.downbutton.configure(state="disabled")
        self.abortbutton.configure(state="disabled")
        self.stop_event.clear()
        self.doshot = threading.Thread(target=lambda: self.shotloop(dvt, app_name, chat_name, ab_count, sc_count, abs_count, direction, imglabel, namefield, text, first=True))
        self.doshot.start()
        
    
    def breakshotloop(self):
        self.stop_event.set()
    
    def shotloop(self, dvt, app_name, chat_name, ab_count, sc_count, abs_count, direction, imglabel, namefield, text, png=None, first=False, seen_hashes=None, first_hash=None):
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
            seen_hashes = []
            if d_class == "Watch":
                try:
                    png = ScreenshotService(lockdown).take_screenshot()
                except:
                    png = Screenshot(dvt).get_screenshot()
            else:
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
            filepath = os.path.join("screenshots", app_name, chat_name, filename)
            hashpath = os.path.join("screenshots", app_name, chat_name, hashname)
            with open(os.path.join(filepath), "wb") as file:
                file.write(png)
            hash_sha256 = hashlib.sha256(png).hexdigest()
            with open(os.path.join(hashpath), "w") as hash_file:
                hash_file.write(hash_sha256)
            log(f"Created screenshot {filename} with hash {hash_sha256}")
            namefield.configure(text=f"Screenshot saved as:\n{filename}\nHash saved as:\n{hashname}")
            first_hash = imagehash.phash(shot)
            seen_hashes.append(first_hash)
            self.pdf_report(pdf_type="screenshot", shot=filename, sha256=hash_sha256, shot_png=filepath, app_name=app_name, chat_name=chat_name, w=wsize, h=hsize)
            self.shotloop(dvt, app_name, chat_name, ab_count, sc_count, abs_count, direction, imglabel, namefield, png=png, text=text, seen_hashes=seen_hashes, first_hash=first_hash)
        else:
            while not self.stop_event.is_set():
                if ab_count >= 8 or abs_count >= 16:
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
                    if d_class == "Watch":
                        try:
                            png = ScreenshotService(lockdown).take_screenshot()
                        except:
                            png = Screenshot(dvt).get_screenshot()
                    else:
                        try:
                            png = Screenshot(dvt).get_screenshot()
                        except: 
                            png = ScreenshotService(lockdown).take_screenshot()
                    png_bytes = BytesIO()
                    png_bytes.write(png)
                    shot = Image.open(png_bytes)
                    l_hash = imagehash.phash(shot)
                    if png != prev:
                        duplicate = any(abs(l_hash - h) <= 3 for h in seen_hashes)
                        if not duplicate:
                            seen_hashes.append(l_hash)
                            hperc = (hsize/float(shot.size[1]))
                            wsize = int((float(shot.size[0])*float(hperc)))
                            if wsize > 300:
                                wsize = 300
                                wperc = (wsize/float(shot.size[0]))
                                hsize = int((float(shot.size[1])*float(wperc)))
                            screensh = ctk.CTkImage(dark_image=shot, size=(wsize, hsize))
                            imglabel.configure(image=screensh)
                            filepath = os.path.join("screenshots", app_name, chat_name, filename)
                            hashpath = os.path.join("screenshots", app_name, chat_name, hashname)
                            with open(os.path.join(filepath), "wb") as file:
                                file.write(png)
                            hash_sha256 = hashlib.sha256(png).hexdigest()
                            with open(os.path.join(hashpath), "w") as hash_file:
                                hash_file.write(hash_sha256)
                            log(f"Created screenshot {filename} with hash {hash_sha256}")
                            namefield.configure(text=f"Screenshot saved as:\n{filename}\nHash saved as:\n{hashname}")
                            self.pdf_report(pdf_type="screenshot", shot=filename, sha256=hash_sha256, shot_png=filepath, app_name=app_name, chat_name=chat_name, w=wsize, h=hsize)
                            sc_count += 1
                            ab_count = 0
                            abs_count = 0
                        else:
                            abs_count += 1
                            if sc_count > 2:
                                ab_count += 1
                            else:
                                pass
                    else:
                        abs_count += 1
                        if sc_count > 2:
                            ab_count += 1

                    if sc_count > 2 and abs(l_hash - first_hash) <= 2:
                            print("is first")
                            self.breakshotloop()
                    self.shotloop(dvt, app_name, chat_name, ab_count, sc_count, abs_count, direction, imglabel, namefield, png=png, text=text, seen_hashes=seen_hashes, first_hash=first_hash)
            text.configure(text="Chat loop stopped.")
            self.upbutton.configure(state="enabled")
            self.downbutton.configure(state="enabled")
            self.abortbutton.configure(state="enabled")
            AccessibilityAudit(lockdown).set_show_visuals(False)
            raise SystemExit
            return("interrupt")
    

# Fileloop window
    def show_fileloop(self, dvt):
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Filesystem content", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
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
        log("Created filesystem list")
        self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("DevMenu")).pack(pady=40))

# Call the fileloop and write the output to a file
    def call_fileloop(self, dvt, waitls, prog_text, progress, folder_text):
        folders = []
        for line in DeviceInfo(dvt).ls("/"):
            folders.append(line)
        fcount = len(folders)
        cnt = 0
        pathlist = set()
        pathlist = fileloop(dvt, "/var", pathlist, fcount, cnt, folder_text, progress, prog_text)
        s_pathlist = sorted(pathlist)
        with open(udid + "_var_filesystem.txt", "w") as files:
            for line in s_pathlist:
                files.write("\n" + line)
        prog_text.configure(text="100%")
        progress.set(1)
        waitls.set(1)

    def call_unmount(self):
        global developer
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Unmounting DeveloperDiskImage", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Trying to unmount the image.", width=585, height=60, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.change = ctk.IntVar(self, 0)
        if int(dversion.split(".")[0]) < 14:
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

    # Print out exception
    def global_exception_handler(self, type, value, tb):
        try:
            if self.text.winfo_ismapped():
                self.text.configure(text=f"Uh-Oh, An error was raised! Check the file:\nufade_log_{udid}.log")
            else:
                self.text = ctk.CTkLabel(self.dynamic_frame, width=400, height=180, font=self.stfont, anchor="w", justify="left")
                self.text.configure(text=f"Error: {value}")
                self.text.pack(pady=50)
        except:
            self.text = ctk.CTkLabel(self.dynamic_frame, width=400, height=180, font=self.stfont, anchor="w", justify="left")
            self.text.configure(text=f"Error: {value}")
            self.text.pack(pady=50)
        log(f"Error: {value}")

    #Unback given Backup
    def show_unback(self, mode):
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        valid_bu = False
        self.bu_folder = None
        self.bu_udid = ""
        bu_pass = ""
        ctk.CTkLabel(self.dynamic_frame, text=f"UFADE by Christian Peter  -  Output: {dir_top}", text_color="#3f3f3f", height=60, padx=40, font=self.stfont).pack(anchor="w")
        ctk.CTkLabel(self.dynamic_frame, text="Unback Backup", height=60, width=585, font=("standard",24), justify="left").pack(pady=20)
        self.text = ctk.CTkLabel(self.dynamic_frame, text="Choose an iTunes Backup directory (encrypted) and\nprovide the correct Backup Password:", width=585, height=40, font=self.stfont, anchor="w", justify="left")
        self.text.pack(anchor="center", pady=25)
        self.backup_text = ctk.CTkLabel(self.dynamic_frame, text="Chosen Backup:    < no backup chosen >", width=585, height=20, font=self.stfont, anchor="w", justify="left")
        self.backup_text.pack(anchor="center", pady= 5)
        self.browsebutton = ctk.CTkButton(self.dynamic_frame, text="Browse", font=self.stfont, command=lambda: self.choose_bu_folder())
        self.browsebutton.pack(anchor="w", padx= 80, pady = 15)
        self.pw_text = ctk.CTkLabel(self.dynamic_frame, text="Enter the Backup Password: ", width=585, height=15, font=self.stfont, anchor="w", justify="left")
        self.pw_text.pack(anchor="center", pady=15)
        self.passwordbox = ctk.CTkEntry(self.dynamic_frame, width=200, height=20, corner_radius=0, show="*")
        self.passwordbox.bind(sequence="<Return>", command=lambda x: self.perf_unback(self.bu_folder))
        self.passwordbox.pack(anchor="w", padx= 80, pady = 5)
        self.passwordbox.configure(state="disabled")
        if mode == "unback":
            self.okbutton = ctk.CTkButton(self.dynamic_frame, text="Unback", font=self.stfont, command=lambda: self.perf_unback(self.bu_folder))
        else:   
            self.okbutton = ctk.CTkButton(self.dynamic_frame, text="Decrypt", font=self.stfont, command=lambda: self.perf_unback(self.bu_folder, dec_type="decrypt"))
        self.okbutton.pack(anchor="w", padx= 80, pady = 15)
        self.okbutton.configure(state="disabled")

        
        self.backbutton = ctk.CTkButton(self.dynamic_frame, text="Back", command=lambda: [self.switch_menu("Data")])
        self.backbutton.pack(anchor="e", pady=10, padx=(0,65))

    def choose_bu_folder(self):
        self.browsebutton.configure(state="disabled")
        if platform.uname().system == 'Linux':
            try:
                import crossfiledialog
                bu_f = crossfiledialog.choose_folder()
            except:
                bu_f = ctk.filedialog.askdirectory()
        else:
            bu_f = ctk.filedialog.askdirectory()
        if not bu_f:
            self.browsebutton.configure(state="enabled")
            return    

        manifest = os.path.join(bu_f, "Manifest.plist")    
        if os.path.isfile(manifest):
            self.bu_folder = bu_f
            try:
                with open(os.path.join(bu_f, "Info.plist"), mode='rb') as infofile:
                    readinfo = plistlib.load(infofile)
                    bu_name = readinfo.get("Device Name", "-")
                    bu_product = readinfo.get("Product Type", "-")
                    bu_version = readinfo.get("Product Version", "-")
                    bu_build = readinfo.get("Build Version", "-")
                    bu_snr = readinfo.get("Serial Number", "-")
                    bu_imei = readinfo.get("IMEI", "-")
                    bu_iccid = readinfo.get("ICCID", "-")
                    bu_udid = readinfo.get("Unique Identifier", "-")
                    bu_phone = readinfo.get("Phone Number", "-")
                    bu_itunes = readinfo.get("iTunes Version", "-")

                if len(bu_udid) > 26:
                    bu_udid_s = bu_udid[:25] + "\n" + '{:13}'.format(" ") + "\t" + bu_udid[25:]
                else:
                    bu_udid_s = bu_udid
                if len(bu_name) > 26:
                    wordnames = bu_name.split()
                    if len(' '.join(wordnames[:-1])) < 27:
                        bu_name_s = ' '.join(wordnames[:-1]) + "\n" + '{:13}'.format(" ") + "\t" + wordnames[-1]
                    else:
                        bu_name_s = ' '.join(wordnames[:-2]) + "\n" + '{:13}'.format(" ") + "\t" + ' '.join(wordnames[-2:])
                else:
                    bu_name_s = bu_name

                device = ("Chosen Backup: \n\n" +
                '{:13}'.format("Dev-Name: ") + "\t" + bu_name_s +
                "\n" + '{:13}'.format("Product: ") + "\t" + bu_product +
                "\n" + '{:13}'.format("Software: ") + "\t" + bu_version +
                "\n" + '{:13}'.format("Build-Nr: ") + "\t" + bu_build +
                "\n" + '{:13}'.format("Serialnr: ") + "\t" + bu_snr +
                "\n" + '{:13}'.format("IMEI: ") + "\t" + bu_imei +
                "\n" + '{:13}'.format("ICCID:: ") + "\t" + bu_iccid +
                "\n" + '{:13}'.format("Number: ") + "\t" + bu_phone +
                "\n" + '{:13}'.format("UDID: ") + "\t" + bu_udid_s +
                "\n" + '{:13}'.format("iTunes: ") + "\t" + bu_itunes +
                "\n\n\n" + 
                "   52 65 6E 65 77 65 64 20 73 68 61 \n" +
                "   6C 6C 20 62 65 20 62 6C 61 64 65 \n" +
                "   20 74 68 61 74 20 77 61 73 20 62 \n" +
                "   72 6F 6b 65 6E 2E ")
                
                self.info_text.configure(state="normal")
                self.info_text.delete("0.0", "end")
                self.info_text.configure(text_color="#abb3bd")
                self.info_text.insert("0.0", device)
                self.info_text.configure(state="disabled")
                

                self.backup_text.configure(text=f"Chosen Backup:    {bu_udid}")
                self.bu_udid = bu_udid
                self.passwordbox.configure(state="normal")
                self.okbutton.configure(state="enabled")
                self.browsebutton.configure(state="enabled")
            
            except:
                self.backup_text.configure(text=f"Chosen Backup:    {os.path.basename(bu_f)}")
                self.bu_udid = os.path.basename(bu_f)
                self.passwordbox.configure(state="normal")
                self.okbutton.configure(state="enabled")



        else: 
            self.backup_text.configure(text="Chosen Backup:    < no backup chosen / or invalid folder >")
            self.browsebutton.configure(state="enabled")
            self.passwordbox.configure(state="disabled")
            self.okbutton.configure(state="disabled")
    
    def perf_unback(self, bu_folder, dec_type="unback"):
        self.text.configure(text="Checking Backup. This might take a while.", height=60)
        self.backup_text.pack_forget()
        self.okbutton.pack_forget()
        bu_pass = self.passwordbox.get()
        self.passwordbox.pack_forget()
        self.pw_text.pack_forget()
        self.browsebutton.pack_forget()
        self.backbutton.pack_forget()
        bu_root = os.path.dirname(bu_folder)
        bu_udid = os.path.basename(bu_folder)

        self.change = ctk.IntVar(self, 0)
        panda_backup = threading.Thread(target=lambda: self.init_backup_decrypt(self.change, udid=bu_udid, bu_pass=bu_pass, backuproot=bu_root))
        panda_backup.start()
        self.wait_variable(self.change)
        if self.change.get() == 1:
            self.after(10, lambda: self.text.configure(text="Decrypting iTunes Backup: "))
            self.prog_text = ctk.CTkLabel(self.dynamic_frame, text="0%", width=585, height=20, font=self.stfont, anchor="w", justify="left")
            self.prog_text.pack() 
            self.progress = ctk.CTkProgressBar(self.dynamic_frame, width=585, height=30, corner_radius=0)
            self.progress.set(0)
            self.progress.pack()
            line_list = []
            line_cnt = 0
            for line in backupfiles['relativePath']:                                                                        
                if(line not in line_list):
                    line_cnt += 1
                    line_list.append(line)
            d_nr = 0
            self.change.set(0)
            if dec_type == "unback":                                                                    
                zipname = f'{self.bu_udid}_unback_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}'                                                     
                zip = zipfile.ZipFile(f'{zipname}.zip', "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1)
                decrypt = threading.Thread(target=lambda: self.decrypt_itunes(b, backupfiles, self.progress, self.prog_text, line_list, line_cnt, d_nr, self.change, l_type="PRFS", zip=zip))
                decrypt.start()
            else:
                outfolder = f'{self.bu_udid}_decrypted_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}'
                decrypt = threading.Thread(target=lambda: self.only_decrypt_itunes(b, backupfiles, self.progress, self.prog_text, line_list, line_cnt, d_nr, self.change, src=bu_folder, folder=outfolder))
                decrypt.start()
            self.wait_variable(self.change)
            if dec_type == "unback":
                self.after(10, lambda: self.text.configure(text=f"The iTunes backup has been decrypted successfully.\nOutput: {zipname}.zip"))
                zip.close()
                try: shutil.rmtree(".tar_tmp")
                except: pass  
            else:
                self.after(10, lambda: self.text.configure(text=f"The iTunes backup has been decrypted successfully.\nOutput: {outfolder}"))
            self.after(50)
            self.text.update()
            self.progress.pack_forget()
            self.prog_text.pack_forget()
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("Data")).pack(pady=40))
            return


        else:
            self.after(50)
            self.text.configure(text="An error occured.\nMake sure you enter the correct backup password.")
            self.text.update()
            self.after(100, lambda: ctk.CTkButton(self.dynamic_frame, text="OK", font=self.stfont, command=lambda: self.switch_menu("Data")).pack(pady=40))
            return




def unmount_abort_timer():
    raise exceptions.UnsupportedCommandError()

def unmount_developer(text, change):
    try:
        if int(dversion.split(".")[0]) >= 17:
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
            elif "/_refs/" in next_path:
                break
            elif "/AssetsV2/" in next_path:
                break
            else:
                pathlist.add(next_path)
                fileloop(dvt, next_path, pathlist, fcount, cnt, folder_text, progress, prog_text) 
    except: 
        pass
    finally:
        return(pathlist)

# Pull Media-files
def media_export(l_type, dest="Media", archive=None, text=None, prog_text=None, progress=None, change=None, fzip=False):
    if l_type == "PRFS":
        media_list = set()
        media_set = set()
    else:
        media_list = []
    tar = archive
    zip = archive
    if fzip == True:
        zip = zipfile.ZipFile(f'Media_{udid}_{datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}.zip', 'w')
    text.configure(text="Performing AFC Extraction of Mediafiles")
    text.update()
    if l_type == "PRFS":
        for line in AfcService(lockdown).dirlist("/", -1):
            #if not line.startswith("/private/var/mobile/Media/PhotoData/Thumbnails/V2/"):
            #    if not line.endswith((".JPG",".HEIC",".MOV")):
            #        media_list.append(line)
            #    else:
            #        pass
            #else:
            #    pass
            media_set.add(line)
        media_list = media_set.difference(m_unback_set)
    else:
        for line in AfcService(lockdown).listdir("/"):
            media_list.append(line)
    if l_type != "folder" and l_type != "PRFS":
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
            if l_type == "PRFS":
                #if (f"/private/var/mobile/Media{entry}") not in unback_set:
                pull_file(self=AfcService(lockdown),relative_src=entry, dst=dest)
                file_path = os.path.join(dest, pathlib.Path(entry).name)
                arcname = os.path.join("/private/var/mobile/Media", entry.strip("/"))
                zip.write(file_path, arcname=arcname)
                os.remove(file_path)
                #else:
                #    pass
            else:
                pull(self=AfcService(lockdown),relative_src=entry, dst=dest)
                if l_type != "folder":
                    file_path = os.path.join(dest, entry)                                                              #get the files and folders shared over AFC
                    if l_type != "UFED":
                        #tar.add(file_path, arcname=os.path.join("Media/", entry), recursive=True)                                   #add the file/folder to the TAR
                        if os.path.isfile(file_path):
                            tar.add(file_path, arcname=os.path.join("Media", entry))                            #add the file/folder to the ZIP
                        elif os.path.isdir(file_path):
                            for root, dirs, files in os.walk(dest):
                                for file in files:
                                    source_file = os.path.join(root, file)
                                    filename = os.path.relpath(source_file, dest)
                                    base_folder = os.path.join(dest, "AirFair")
                                    if dest.startswith(base_folder):
                                        filename = os.path.relpath(source_file, os.path.join(dest, "AirFair"))
                                    tar.add(source_file, arcname=os.path.join("Media", filename))
                    else:
                        if os.path.isfile(file_path):
                            zip.write(file_path, os.path.join("iPhoneDump/AFC Service/", entry))                            #add the file/folder to the ZIP
                        elif os.path.isdir(file_path):
                            for root, dirs, files in os.walk(dest):
                                for file in files:
                                    source_file = os.path.join(root, file)
                                    filename = os.path.relpath(source_file, dest)
                                    zip.write(source_file, os.path.join("iPhoneDump/AFC Service/", filename))
                    try: os.remove(file_path)
                    except: shutil.rmtree(file_path)
                else:
                    if fzip == True:
                        file_path = os.path.join(dest, entry) 
                        if os.path.isfile(file_path):
                            zip.write(file_path, os.path.join("private/var/Media/", entry))                            #add the file/folder to the ZIP
                        elif os.path.isdir(file_path):  
                            for root, dirs, files in os.walk(dest):
                                for file in files:
                                    source_file = os.path.join(root, file)
                                    filename = os.path.relpath(source_file, dest)
                                    zip.write(source_file, os.path.join("private/var/Media/", filename))
                        try: os.remove(file_path)
                        except: shutil.rmtree(file_path)
                    else:
                        pass
        except:
            pass

    if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
        with open(f"afc_files_{udid}.json", "w") as file:
            json.dump(filedict, file)
    else:
        pass
    if fzip == True:
        zip.close()
        shutil.rmtree(dest)
    log("Extracted AFC-Media files")
    change.set(1)   
    return(archive)  



# Pull crash logs
def crash_report(crash_dir, change, progress, prog_text, czip=False, tar=None, zip=None, tarpath=None, l_type="default"):
    log("Starting crash log extraction")
    if czip == True:
        zip = zipfile.ZipFile(f'{crash_dir}.zip', 'w')
    crash_count = 0
    crash_list = []
    try:
        for entry in CrashReportsManager(lockdown).ls(""):
            crash_list.append(entry)
            crash_count += 1        
        try: os.mkdir(crash_dir)
        except: pass
        c_nr = 0
        for entry in crash_list:
            c_nr += 1
            try: 
                pull(self=AfcService(lockdown, service_name="com.apple.crashreportcopymobile"),relative_src=entry, dst=crash_dir)
                #AfcService(lockdown, service_name="com.apple.crashreportcopymobile").pull(relative_src=entry, dst=crash_dir, src_dir="")
                if czip == True:
                    file_path = os.path.join(crash_dir, entry) 
                    if os.path.isfile(file_path):
                        #add the file/folder to the ZIP
                        zip.write(file_path, entry)                            
                    elif os.path.isdir(file_path):  
                        for root, dirs, files in os.walk(crash_dir):
                            for file in files:
                                source_file = os.path.join(root, file)
                                filename = os.path.relpath(source_file, crash_dir)
                                zip.write(source_file, filename)
                    try: os.remove(file_path)
                    except: shutil.rmtree(file_path)
                elif tar != None:
                    file_path = os.path.join(crash_dir, entry) 
                    if os.path.isfile(file_path):
                        tar.add(file_path, arcname=os.path.join(tarpath, entry))
                    elif os.path.isdir(file_path):  
                        for root, dirs, files in os.walk(crash_dir):
                            for file in files:
                                source_file = os.path.join(root, file)
                                filename = os.path.relpath(source_file, crash_dir)
                                tar.add(source_file, arcname=os.path.join(tarpath, filename))
                    try: os.remove(file_path)
                    except: shutil.rmtree(file_path)
                elif zip is not None and l_type == 'PRFS':
                    file_path = os.path.join(crash_dir, entry) 
                    if os.path.isfile(file_path):
                        zip.write(file_path, os.path.join(tarpath, entry))
                    elif os.path.isdir(file_path):  
                        for root, dirs, files in os.walk(crash_dir):
                            for file in files:
                                source_file = os.path.join(root, file)
                                filename = os.path.relpath(source_file, crash_dir)
                                zip.write(source_file, os.path.join(tarpath, filename))
                    try: os.remove(file_path)
                    except: shutil.rmtree(file_path)

                else:
                    pass
            except: 
                pass
            cpro = c_nr/crash_count
            progress.set(cpro)
            prog_text.configure(text=f"{int(cpro*100)}%")
            progress.update()
            prog_text.update()
        if czip == True:
            zip.close()
            shutil.rmtree(crash_dir)
        log("Crash log extraction complete.")
        change.set(1)
    except:
        log("Crash log extraction failed.")
        change.set(1)



def save_info():
    file = open("device_" + udid + ".txt", "w", encoding='utf-8')
    file.write("## DEVICE ##\n\n" + "Model-Nr:   " + dev_name + "\nDev-Name:   " + name + "\nHardware:   " + hardware_mnr + "\nProduct:    " + product +
        "\nSoftware:   " + dversion + "\nBuild-Nr:   " + build + "\nLanguage:   " + language + "\nSerialnr:   " + snr + "\nMLB-snr:    " + mlbsnr +
        "\nWifi MAC:   " + w_mac + "\nBT-MAC:     " + b_mac + "\nCapacity:   " + disk + " GB" + "\nFree Space: " + free + " GB" +
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
            try: file.write("\n\n## SIM-Info ##\n\nICCID:  " + entry["IntegratedCircuitCardIdentity"] + 
                                    "\nIMSI:   " + entry["InternationalMobileSubscriberIdentity"] + 
                                    "\nMCC:    " + entry["MCC"] + 
                                    "\nMNC:    " + entry["MNC"] +
                                    "\nSlot:   " + entry["Slot"])
            except: pass
    
    #Save user-installed Apps to txt
    if int(dversion.split(".")[0]) >= 14:
        try:
            springboard = SpringBoardServicesService(lockdown).get_icon_state()
        except:
            springboard = None
    else:
        springboard = None
    try: al = str(len(max(app_id_list, key=len)))  
    except: al = 40 
    file.write("\n\n" + "## Installed Apps (by user) ## \n\n")
    if len(apps) > 0:
        file.write('{:{l}}'.format("app name", l=20) + "\t" + '{:{l}}'.format("bundle id", l=al) + "\t sharing")
    else:
        file.write('None')
    if springboard != None:
        file.write("\tspringboard\n")
    else:
        file.write("\n")
    for app in app_id_list:
        app_name = apps.get(app)['CFBundleDisplayName']
        if len(app_name) > 20:
            app_name = f'{app_name[:17]}...'
        try: 
            apps.get(app)['UIFileSharingEnabled']
            sharing = 'yes'
        except:
            sharing = 'no'
        if springboard != None:
            if app in str(springboard):
                state = "visible"
            else:
                state = "absent"
        file.write("\n" + '{:{l}}'.format(app_name, l=20) + "\t" + '{:{l}}'.format(app, l=al) + "\t [" + sharing + "]")
        if springboard != None:
            file.write("\t\t" + state)

    file.close()
    log("Wrote device info to text")    

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

def pair_supervised_device(paired):
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
    global mode
    global dev_name
    global hardware
    global product
    global ecid
    global snr
    global udid
    global nodevice_text
    try: 
        r_mode = irecv.IRecv(timeout=0.01).mode
        if "RECOVERY" in str(r_mode):
            mode = "Recovery"
        elif "DFU" in str(r_mode):
            mode = "DFU"
    except:
        mode = "normal"

    if mode != "normal":
        try: dev_name = irecv.IRecv().display_name
        except: dev_name = "Apple device"
        try: hardware = irecv.IRecv().hardware_model
        except: hardware = " "
        try: product = irecv.IRecv().product_type
        except: product = " "
        try: irec_val = ast.literal_eval(str(irecv.IRecv()))
        except: irec_val = {}
        try: ecid = irec_val['ECID']
        except: ecid = " "
        try: snr = irec_val['SRNM']
        except: snr = " "
        try: iboot = irecv.IRecv().getenv('build-version').decode().rstrip('\x00')
        except: iboot = " "
        try: cpid = irec_val['CPID']
        except: cpid = ""
        try:
            if "iPhone" in str(product):
                if int(product.split(",")[0].strip('iPhone')) >= 11:
                    udid = f"{cpid.zfill(8)}-{ecid.zfill(16)}"
                else:
                    udid = "unavailable"
            else:
                udid = "unavailable"
        except:
            udid = "unavailable"


        device = ("Device is in " + mode + " mode \n\n" +
            '{:13}'.format("Model-Nr: ") + "\t" + dev_name +
                "\n" + '{:13}'.format("Hardware: ") + "\t" + hardware +
                "\n" + '{:13}'.format("Product: ") + "\t" + product +
                "\n" + '{:13}'.format("Serialnr: ") + "\t" + snr +
                "\n" + '{:13}'.format("iBOOT: ") + "\t" + iboot +
                "\n" + '{:13}'.format("UDID: ") + "\t" + udid +
                "\n" + '{:13}'.format("ECID: ") + "\t" + str(int(ecid, 16)) +
                "\n" + '{:13}'.format("CPID: ") + "\t" + cpid +
                "\n\n\n\n\n\n" + 
                "   42 75 74 20 69 6E 20 74 68 65 20 \n" +
                "   65 6E 64 20 69 74 27 73 20 6F 6E \n" +
                "   6C 79 20 61 20 70 61 73 73 69 6E \n" +
                "   67 20 74 68 69 6E 67 2C 20 74 68 \n" +
                "   69 73 20 73 68 61 64 6F 77 3B 20 \n" +
                "   65 76 65 6E 20 64 61 72 6B 6E 65 \n" +
                "   73 73 20 6D 75 73 74 20 70 61 73 \n" +
                "   73 2E")  
    else:
        if lockdown != None:
            global d_class 
            try: d_class= lockdown.get_value("","DeviceClass")
            except: d_class = " "
            
            try: 
                dev_name = lockdown.display_name
                if dev_name == None:
                    if d_class == "Watch":
                        dev_name = "Apple Watch"
                    elif d_class == "AppleTV":
                        dev_name = "Apple TV"
                    elif d_class == "iPod":
                        dev_name = "iPod Touch"
                    elif d_class == "iPad":
                        dev_name = "iPad"
                    elif d_class == "iPhone":
                        dev_name = "iPhone"
                    else:
                        dev_name = "Apple device"
            except: 
                dev_name = "Apple device"
            try: 
                hardware = lockdown.hardware_model
                if hardware == None:
                    hardware = " "
            except: 
                hardware = " "
            try: 
                product = lockdown.product_type
                if product == None:
                    product = lockdown.get_value("","ProductType")
                    if product == None:
                        product = d_class
            except: 
                product = d_class
            try: udid = lockdown.udid
            except: udid = " "
            try: ecid = str(lockdown.ecid)
            except: ecid = " "
            global dversion
            try: dversion = lockdown.product_version
            except: dversion = " "
            global w_mac 
            try: w_mac = lockdown.wifi_mac_address
            except: w_mac = " "
            global name
            try: name =  lockdown.get_value("","DeviceName")
            except: name = " "
            global build
            try: build = lockdown.get_value("","BuildVersion")
            except: build = " "
            if ispaired == True:
                global imei
                global imei2
                try: imei = lockdown.get_value("","InternationalMobileEquipmentIdentity")
                except: imei = " "
                try: imei2 = lockdown.get_value("","InternationalMobileEquipmentIdentity2")
                except: imei2 = " "
                try: snr = lockdown.get_value("","SerialNumber")
                except: snr = " "
                global mlbsnr 
                try: mlbsnr = lockdown.get_value("","MLBSerialNumber")
                except: mlbsnr = " "
                global d_tz 
                try: d_tz = lockdown.get_value("","TimeZone")
                except: d_tz = " "
                global b_mac
                try: b_mac = lockdown.get_value("","BluetoothAddress")
                except: b_mac = " "
                global mnr
                try: mnr = lockdown.get_value("", "ModelNumber")
                except: mnr = " "
                global hardware_mnr
                if hardware == " ":
                    hardware_mnr = mnr
                else:
                    hardware_mnr = f"{hardware}, {mnr}"
                global disk1 
                disk1 = lockdown.get_value("com.apple.disk_usage","TotalDiskCapacity")/1000000000
                global disk 
                disk = f'{round(disk1,2):.2f}'
                global free1 
                free1 = lockdown.get_value("com.apple.disk_usage","AmountDataAvailable")/1000000000
                global free 
                free = f'{round(free1,2):.2f}'
                global used1 
                used1 = disk1 - free1
                global used 
                used = f'{round(used1,2):.2f}'
                global graph_progress 
                graph_progress = "" + "▓" * int(26/100*(100/disk1*used1)) + "░" * int(26/100*(100/disk1*free1)) + ""
                global language
                try: language = lockdown.language
                except: language = " "
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
                    "\n" + '{:13}'.format("Hardware: ") + "\t" + hardware_mnr +
                    "\n" + '{:13}'.format("Product: ") + "\t" + product +
                    "\n" + '{:13}'.format("Software: ") + "\t" + dversion +
                    "\n" + '{:13}'.format("Build-Nr: ") + "\t" + build +
                    "\n" + '{:13}'.format("Language: ") + "\t" + language +
                    "\n" + '{:13}'.format("Serialnr: ") + "\t" + snr +
                    "\n" + '{:13}'.format("MLB-Snr: ") + "\t" + mlbsnr +
                    "\n" + '{:13}'.format("Wifi MAC: ") + "\t" + w_mac +
                    "\n" + '{:13}'.format("BT MAC: ") + "\t" + b_mac +
                    "\n" + '{:13}'.format("Disk Use: ") + "\t" + graph_progress +
                    "\n" + '{:13}'.format("Capacity: ") + "\t" + disk + " GB" +
                    "\n" + '{:13}'.format("Used: ") + "\t" + used + " GB" +
                    "\n" + '{:13}'.format("Free: ") + "\t" + free + " GB" +
                    "\n" + '{:13}'.format("UDID: ") + "\t" + udid_s +
                    "\n" + '{:13}'.format("ECID: ") + "\t" + ecid)
                
                if imei != " ":
                    device = device + "\n" + '{:13}'.format("IMEI 1: ") + "\t" + imei
                if imei2 != " ":
                    device = device + "\n" + '{:13}'.format("IMEI 2: ") + "\t" + imei2
            else:
                device = ("Device unpaired ✗ \n\n" +
                '{:13}'.format("Model-Nr: ") + "\t" + dev_name_s +
                    "\n" + '{:13}'.format("Dev-Name: ") + "\t" + name_s +
                    "\n" + '{:13}'.format("Hardware: ") + "\t" + hardware +
                    "\n" + '{:13}'.format("Product: ") + "\t" + product +
                    "\n" + '{:13}'.format("Software: ") + "\t" + dversion +
                    "\n" + '{:13}'.format("Build-Nr: ") + "\t" + build +
                    "\n" + '{:13}'.format("Wifi MAC: ") + "\t" + w_mac +
                    "\n" + '{:13}'.format("UDID: ") + "\t" + udid_s +
                    "\n" + '{:13}'.format("ECID: ") + "\t" + ecid)  

        except: 
            device = nodevice_text

        #Get installed Apps
        if lockdown != None and ispaired != False:
            global apps 
            global all_apps
            global app_id_list 
            try:
                all_apps = installation_proxy.InstallationProxyService(lockdown).get_apps()
                apps = installation_proxy.InstallationProxyService(lockdown).get_apps("User")
                app_id_list = []
                sorted_apps = sorted(apps.keys(), key=lambda app: apps.get(app).get('CFBundleDisplayName', '').lower())
                for app in sorted_apps:
                    app_id_list.append(app)
                global doc_list
                doc_list = []
                for app in sorted_apps:
                    try: 
                        apps.get(app)['UIFileSharingEnabled']
                        doc_list.append("yes")
                    except:
                        doc_list.append("no")
            except:
                apps = {}
                all_apps = {}
                app_id_list = []
        else:
            pass
    return(device)

#Alternative pmd3 Backup for supervising without escrow_bag
class UFADEMobilebackup2Service:
    def __init__(self, lockdown: LockdownClient):
        global no_escrow
        try:
            escrow = lockdown.pair_record['EscrowBag']
        except:
            no_escrow = True
        self._service = Mobilebackup2Service.__new__(Mobilebackup2Service)
        if no_escrow == True:
            setattr(self._service, 'include_escrow_bag', False)
            LockdownService.__init__(self._service, lockdown, Mobilebackup2Service.SERVICE_NAME, include_escrow_bag=False)
        else:
            setattr(self._service, 'include_escrow_bag', True)
            LockdownService.__init__(self._service, lockdown, Mobilebackup2Service.SERVICE_NAME, include_escrow_bag=True)

    def __getattr__(self, name):
        return getattr(self._service, name)

def keybag_from_p12(p12file, password: str):
    global pub_key
    p12path = pathlib.Path(p12file)
    keystore_data = p12path.read_bytes()
    try:
        decrypted_p12 = load_pkcs12(keystore_data, password.encode('utf-8'))
        file = pathlib.Path(f'{p12file.rsplit(".",1)[0]}.cer')
        private_key = decrypted_p12.key
        cer = decrypted_p12.cert.certificate
        file.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ) + cer.public_bytes(encoding=serialization.Encoding.PEM))
        pub_key = cer.public_bytes(encoding=serialization.Encoding.PEM)
        return file
    except Exception as pkcs12_error:
        return "error"


# modified pull function from pymobiledevice3 (sets atime to mtime as it's not readable)
def pull(self, relative_src, dst, callback=None, src_dir=''):
        global filedict

        src = self.resolve_path(posixpath.join(src_dir, relative_src))

        if not self.isdir(src):
            # normal file
            output_format = "%Y-%m-%dT%H:%M:%S+00:00"
            try: 
                filecontent = self.get_file_contents(src)
                readable = 1
            except:
                log(f"Error reading file: {src}")
                readable = 0
            if readable == 1:
                if d_class == "Watch" or d_class == "AppleTV" or d_class == "AudioAccessory":
                    textfiles = [".txt", ".doc", ".docx", ".odt"]
                    dbfiles = [".db", ".sqlite", ".realm", ".kgdb"]
                    configfiles = [".plist", ".xml"]
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
                        elif any(x in src.lower() for x in dbfiles):
                            tag = "Database"
                        elif any(x in src.lower() for x in configfiles):
                            tag = "Configuration"
                        else: 
                            tag = "Uncategorized"
                        #print(src)
                        #print(mimetype)
                        #print(tag)
                    except:
                        mimetype = ["uncategorized", None]
                        if any(x in src.lower() for x in dbfiles):
                            tag = "Database"
                        else: 
                            tag = "Uncategorized"
                    finally:
                        filedict[str(src)] = {"size": str(self.stat(src)['st_size']), "accessInfo": {"CreationTime": f"{self.stat(src)['st_birthtime'].strftime(output_format)}", "ModifyTime": f"{self.stat(src)['st_mtime'].strftime(output_format)}", "AccessTime": ""}, 
                        "metadata": {"Local Path": f"files/AFC_Media/{str(src)}", "SHA256": hashlib.sha256(filecontent).hexdigest(), "MD5": hashlib.md5(filecontent).hexdigest(), "Tags": tag}}
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
                                try: exifdict['ExifEnumPixelXDimension'] = str(etags['EXIF ExifImageWidth'])
                                except: pass
                                try: exifdict['ExifEnumPixelYDimension'] = str(etags['EXIF ExifImageLength'])
                                except: pass
                                try: exifdict['ExifEnumOrientation'] = str(etags["Image Orientation"])
                                except: pass
                                try: exifdict['ExifEnumDateTimeOriginal'] = datetime.fromisoformat(str(etags["EXIF DateTimeOriginal"]).replace(":","").replace(" ", "T")).strftime("%d/%m/%Y %H:%M:%S") + (f" {etags['EXIF OffsetTime']}")
                                except: pass
                                try: exifdict['ExifEnumDateTimeDigitized'] = datetime.fromisoformat(str(etags["EXIF DateTimeDigitized"]).replace(":","").replace(" ", "T")).strftime("%d/%m/%Y %H:%M:%S") + (f" {etags['EXIF OffsetTime']}")
                                except: pass
                                try: exifdict['ExifEnumMake'] = str(etags["Image Make"])
                                except: pass
                                try: exifdict['ExifEnumModel'] = str(etags["Image Model"])
                                except: pass
                                try: exifdict['ExifEnumExposureTime'] = eval(str(etags["EXIF ExposureTime"]))
                                except: pass
                                try: exifdict['ExifEnumFocalLength'] = eval(str(etags["EXIF FocalLength"]))
                                except: pass
                                try: exifdict['ExifEnumFNumber'] = eval(str(etags["EXIF FNumber"]))
                                except: pass
                                try: exifdict['EXIFCameraMaker'] = str(etags["Image Make"])
                                except: pass
                                try: exifdict['EXIFCameraModel'] = str(etags["Image Model"])
                                except: pass
                                try: exifdict['EXIFCaptureTime'] = str(etags["EXIF DateTimeOriginal"])
                                #try: exifdict['EXIFCaptureTime'] = str(datetime.strptime(etags["EXIF DateTimeOriginal"], '%Y:%m:%d %H:%M:%S').strftime("%d.%m.%Y %H:%M:%S")) 
                                except: pass
                                try: exifdict['MetaDataPixelResolution'] = f"{str(etags['EXIF ExifImageWidth'])}x{str(etags['EXIF ExifImageLength'])}"
                                except: pass
                                try: exifdict['EXIFOrientation'] = str(etags["Image Orientation"])
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
                                    try: exifdict['MetaDataLatitudeAndLongitude'] = f"{gpsdict['Longitude']} / {gpsdict['Longitude']}"
                                    except: pass
                                    filedict[str(src)]["GPS"] = gpsdict
                else:
                    pass                
                try: mtime = self.stat(src)['st_mtime'].timestamp()
                except: pass
                if os.path.isdir(dst):
                    dst = os.path.join(dst, os.path.basename(relative_src))
                try:
                    fileout = dst
                    if platform.uname().system == 'Windows':
                        dst = re.sub(r"[?%*:|\"<>\x7F\x00-\x1F]", "-", dst)
                        if dst != fileout:
                            log(f"Renamed {fileout} to {dst}")    
                    with open(dst, 'wb') as f:
                        f.write(filecontent)
                    try:
                        if mtime < datetime.fromisoformat('1980-01-01').timestamp():
                            mtime = datetime.fromisoformat('1980-01-01').timestamp() 
                        os.utime(dst, (mtime, mtime))
                    except: 
                        pass
                    if callback is not None:
                        callback(src, dst)
                except:
                    log(f"Error writing file: {src}")
                    pass
            else:
                pass
                    
        else:
            # directory
            dst_path = pathlib.Path(dst) / os.path.basename(relative_src)
            dst_path.mkdir(parents=True, exist_ok=True)

            for filename in self.listdir(src):
                src_filename = posixpath.join(src, filename)
                dst_filename = dst_path / filename

                src_filename = self.resolve_path(src_filename)

                try:
                    if self.isdir(src_filename):
                        dst_filename.mkdir(exist_ok=True)
                        pull(self, src_filename, str(dst_path), callback=callback,)
                        continue

                    pull(self, src_filename, str(dst_path), callback=callback)
                except:
                    log(f"Error pulling folder: {src_filename}")
                    pass

#Parse artifacts from Sysdiagnose
def sysdiag(tarpath):
    wifi_date_format = "%Y-%m-%d %H:%M:%S.%f"
    output_format = "%Y-%m-%dT%H:%M:%S+00:00"
    diagdict = {}
    iclouddev = []
    k_wifi_list = []
    wifi_known = []
    dev_events = []
    tar = tarfile.open(tarpath)
    members = tar.getmembers()
    for member in members:
        if member.name.endswith("/otctl_status.txt") or member.name == "otctl_status.txt":
            serials = []
            otctl_file = tar.extractfile(member)
            try:
                otctl_content = json.load(otctl_file)
                try:
                    if otctl_content.get("contextDump") != None:
                        peers = otctl_content["contextDump"]["peers"]
                    else:
                        peers = otctl_content["peers"]
                    for elem in peers:
                        model = elem["permanentInfo"]["model_id"]
                        m_name = DEVICE_MAP.get(model, model)
                        if m_name == None:
                            m_name = model
                        os_bnum = elem["stableInfo"]["os_version"]
                        serial = elem["stableInfo"]["serial_number"]
                        if serial not in serials:
                            serials.append(serial)
                            iclouddev.append([model,m_name,os_bnum,serial])
                    diagdict["iclouddev"] = iclouddev
                except:
                    pass
            except:
                log("Error reading otctl_status.txt")
        
        if member.name.endswith("/com.apple.wifi.known-networks.plist") or member.name == "com.apple.wifi.known-networks.plist":
            known_wifi = tar.extractfile(member)
            try:
                k_wifi_cont = plistlib.load(known_wifi)
                for elem in k_wifi_cont:
                    sfile = "com.apple.wifi.known-networks.plist"
                    known = k_wifi_cont.get(elem)
                    ssid = known.get("SSID").decode('UTF-8', errors='ignore')
                    try: end_time = datetime.strptime(str(known.get("UpdatedAt")).strip(), wifi_date_format).strftime(output_format)
                    except: end_time = ""
                    try: time_stamp = datetime.strptime(str(known.get("AddedAt")).strip(), wifi_date_format).strftime(output_format)
                    except: time_stamp = ""
                    try: last_connect = datetime.strptime(str(known.get("JoinedBySystemAt")).strip(), wifi_date_format).strftime(output_format)
                    except: last_connect = ""
                    secure = known.get("SupportedSecurityTypes")
                    os_spec = known.get("__OSSpecific__")
                    bssid = os_spec.get("BSSID")
                    k_wifi_list.append([last_connect, time_stamp, end_time, bssid, ssid, secure, sfile])
            except:
                log("com.apple.wifi.known-networks.plist")

        if member.name.endswith("/com.apple.wifi.plist") or member.name == "com.apple.wifi.plist":
            known_wifi = tar.extractfile(member)
            try:
                k_wifi_cont = plistlib.load(known_wifi)
                if 'List of known networks' in k_wifi_cont:
                    for known in k_wifi_cont['List of known networks']:
                        sfile = "com.apple.wifi.plist"
                        ssid =  known.get("SSID_STR")
                        bssid = known.get("BSSID")
                        try: end_time = datetime.strptime(str(known.get("lastUpdated")).strip(), wifi_date_format).strftime(output_format)
                        except: end_time = ""
                        try: time_stamp = datetime.strptime(str(known.get("addedAt")).strip(), wifi_date_format).strftime(output_format)
                        except: time_stamp = ""
                        try: last_connect = datetime.strptime(str(known.get("lastJoined")).strip(), wifi_date_format).strftime(output_format)
                        except: last_connect = ""
                        secure = None
                        k_wifi_list.append([last_connect, time_stamp, end_time, bssid, ssid, secure, sfile])
            except:
                log("Error reading com.apple.wifi.plist")

        if member.name.endswith("/com.apple.wifi-private-mac-networks.plist") or member.name == "com.apple.wifi-private-mac-networks.plist":
            try:
                known_wifi = tar.extractfile(member)
                k_wifi_cont = plistlib.load(known_wifi)
                if 'List of scanned networks with private mac' in k_wifi_cont:
                    for known in k_wifi_cont['List of scanned networks with private mac']:
                        sfile = "com.apple.wifi-private-mac-networks.plist"
                        ssid =  known.get("SSID_STR")
                        bssid = known.get("BSSID")
                        try: end_time = datetime.strptime(str(known.get("lastUpdated")).strip(), wifi_date_format).strftime(output_format)
                        except: end_time = ""
                        try: time_stamp = datetime.strptime(str(known.get("addedAt")).strip(), wifi_date_format).strftime(output_format)
                        except: time_stamp = ""
                        try: last_connect = datetime.strptime(str(known.get("lastJoined")).strip(), wifi_date_format).strftime(output_format)
                        except: last_connect = ""
                        secure = None
                        k_wifi_list.append([last_connect, time_stamp, end_time, bssid, ssid, secure, sfile])
            except:
                log("Error reading com.apple.wifi-private-mac-networks.plist")

        if "mobileactivationd.log" in member.name:
            log_date_format = "%a %b %d %H:%M:%S %Y"
            try:
                activation = tar.extractfile(member)
                actilog = io.TextIOWrapper(activation, encoding="utf-8", errors="ignore")
                for line in actilog:
                    if "____________________ Mobile Activation Startup _____________________" in line:
                        startup = re.match(r'^([A-Za-z]{3} [A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4})', line)
                        sfile = os.path.basename(member.name)
                        try: 
                            starttime_orig = startup.group(1)
                            starttime = datetime.strptime(starttime_orig.strip(), log_date_format).strftime(output_format)
                            dev_events.append(["Power on", starttime, sfile])
                        except:
                            pass
            except:
                log("Error reading mobileactivationd.log")

        if member.name.endswith("/FDRDiagnosticReport.plist") or member.name == "FDRDiagnosticReport.plist":
            try:
                fdrdiag = tar.extractfile(member)
                fdr = plistlib.load(fdrdiag)
                seid = next((elem["seid"]["LiveProperty"] for elem in fdr["VerifiedProperties"] if "seid" in elem), None)
                diagdict["seid"] = seid
            except:
                log("Error reading FDRDiagnosticReport.plist")
    
    if k_wifi_list != []:
        diagdict["known_wifi"] = k_wifi_list
    if dev_events != []:
        diagdict["device_events"] = dev_events
    return(diagdict)

#pull single file
def pull_file(self, relative_src, dst, callback=None, src_dir=''):
        src = self.resolve_path(posixpath.join(src_dir, relative_src))
        if not self.isdir(src):
            output_format = "%Y-%m-%dT%H:%M:%S+00:00"
            try: 
                filecontent = self.get_file_contents(src)
                readable = 1
            except:
                log(f"Error reading file: {src}")
                readable = 0
            if readable == 1:
                try: mtime = self.stat(src)['st_mtime'].timestamp()
                except: pass
                if os.path.isdir(dst):
                    #dst = os.path.join(dst, os.path.basename(relative_src))
                    dst = os.path.join(dst, pathlib.Path(relative_src).name)
                try:    
                    with open(dst, 'wb') as f:
                        f.write(filecontent)
                    try:
                        if mtime < datetime.fromisoformat('1980-01-01').timestamp():
                            mtime = datetime.fromisoformat('1980-01-01').timestamp() 
                        os.utime(dst, (mtime, mtime))
                    except: 
                        pass
                    if callback is not None:
                        callback(src, dst)
                except:
                    log(f"Error writing file: {src}")
                    pass
            else:
                pass
        else:
            pass

#UFADE "logging"
def log(text):
    try: log_udid = udid
    except: log_udid = "data_operations"
    with open(f"ufade_log_{log_udid}.log", 'a', encoding="utf-8") as logfile:
        logtime = str(datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
        logfile.write(f"{logtime}: {text}\n")

# modified unback command from pyiosbackup for better Windows support
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

def thread_exception_handler(args):
    error = exc_info=(args.exc_type, args.exc_value, args.exc_traceback)
    log(f"Error: {error}")

if getattr(sys, 'frozen', False):
    threading.excepthook = thread_exception_handler

tunnel = False
try:
    if sys.argv[1] == "tunnel":
        tunnel = True
        cli_tunneld(["-d"], standalone_mode=False)
    else:
        pass
except Exception as e:
    print(f"Tunnel-error: {e}")
    raise
#if tunnel == True:
#    sys.exit(0)
#else:
#    pass

lockdown = check_device()
try:
    language = lockdown.language
    ispaired = True
    log(f"Paired with device: {udid}")
except:
    ispaired = False

guiv = "default"
try:
    if sys.argv[1] == "1368":
        guiv = "1368"
    elif sys.argv[1] == "1024":
        guiv = "1024"
    else:
        pass
except:
    pass


if guiv == "default":
    resx = 1100
    resy = 600
    leftx = 340
    rightx = 760
    fsize = 14
    b_button_offset_x = 415
    b_button_offset_y = 410
    sb_button_offset_x = 525
    right_content = 400

elif guiv == "1024":
    resx = 1024
    resy = 600
    leftx = 330
    rightx = 694
    fsize = 14
    b_button_offset_x = 355
    b_button_offset_y = 410
    sb_button_offset_x = 525
    right_content = 360

elif guiv == "1368":
    resx = 1358
    resy = 764
    leftx = 460
    rightx = 800
    fsize = 16
    b_button_offset_x = 545
    b_button_offset_y = 460
    sb_button_offset_x = 655
    right_content = 500

nodevice_text = ("No device detected!\n" +
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

DEVICE_MAP = {device.product_type: device.display_name for device in IRECV_DEVICES}
doc_list = []
pub_key = ""
mode = "normal"
bu_fin = False
device = dev_data()
bu_pass = "12345"
developer = False
filedict = {}
unback_set = set()
m_unback_set = set()
no_escrow = False
case_number = ""
case_name = ""
evidence_number = ""
examiner = ""
u_version = "1.0.3"






# Start the app
if __name__ == "__main__":
    app = MyApp()
    app.mainloop()

#Restart the app
def restart():
    app.destroy()
    app = MyApp()
    app.mainloop()


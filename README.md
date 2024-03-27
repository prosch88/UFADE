# UFADE
**Universal Forensic Apple Device Extractor**

This is a python script written for my masters thesis in IT-Security and Forensics at the [Wismar University](https://www.hs-wismar.de/).

It utitilizes the awesome projects: [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) and [iOSbackup](https://github.com/avibrazil/iOSbackup) to automate the acquisition of Apple mobile devices. Options can be selected via a dialog.

The use of [pythondialog](https://github.com/frougon/pythondialog) is preventig the Windows compatibility atm. Linux and MacOS should work. 

Requires Python >= 3.11.

More features may follow.

<br />

## Installation

**Clone the repo:**
```
git clone https://github.com/prosch88/UFADE
```
To use the developer features you need to mount a DeveloperDisk image on the device. A submodule with images can be loaded while cloning:
```
git clone https://github.com/prosch88/UFADE --recurse-submodules
```
**Install the requirements:**
```
pip install -r requirements.txt 
```
**Install dialog:**

Arch / Manjaro:
```
sudo pacman -S dialog
```
Debian / Ubuntu:
```
sudo apt-get install dialog
```
CentOS / Red Hat:
```
sudo yum install dialog
```
MacOS:
```
brew install dialog
```
<br />

## Usage

Connect an Apple device (iPhone, iPad) to your workstation, unlock and pair the device.
Start the script:
```
python ufade.py
```
Possibly the trust-message is shown on the deviece screen. Confirm with "trust".
Now you should see the device information screen and will be prompted to choose a working directory.
By default, the script is setting this to the directory from which it has been called.

In the main menu you have the options:

**Save device information to text**

Save device information and a list of user-installed apps to a textfile.

**Logical (iTunes-Style) Backup**

Perform a backup as iTunes would do (with an option to bruteforce an unknown backup-password)

**Logical+ Backup**

Perform and decrypt an iTunes backup, gather AFC-media files, shared App folders and crash reports. Creates a TAR-archive.

**Logical+ Backup (UFED-Style)**

Creates an "advanced Logical Backup" as ZIP-archive with an UFD file to load in the [Cellebrite Physical Analyzer©](https://cellebrite.com/de/cellebrite-physical-analyzer-de/)

**Collect Unified Logs**

Collects the AUL from the device and saves them as a logarchive.

<br />

Like this tool? 

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/I3I3H646F)




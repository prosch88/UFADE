# UFADE
**Universal Forensic Apple Device Extractor**

This is a python script written for my masters thesis in IT-Security and Forensics at the [Wismar University](https://www.hs-wismar.de/).

It utilizes the awesome projects: [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) and [iOSbackup](https://github.com/avibrazil/iOSbackup) to automate the acquisition of Apple mobile devices. Options can be selected via a dialog. The SSH access is realized via [Paramiko](https://github.com/paramiko/paramiko).

The use of [pythondialog](https://github.com/frougon/pythondialog) is preventing the Windows compatibility for the command line version. Linux and MacOS should work. 

Update: There is a new version based on [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter). This one works on Windows. You can also load the Windows version from the release page. 

Requires Python == 3.11.

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

**Install Dialog (and libasound2-dev on Debian):**

Arch / Manjaro:
```
sudo pacman -S dialog
```
Debian / Ubuntu:
```
sudo apt-get install dialog libasound2-dev
```
CentOS / Red Hat:
```
sudo yum install dialog
```
MacOS:
```
brew install dialog
```
for the GUI-version on MacOS:
```
brew install python@3.11 python-tk@3.11
```

**Install the requirements:**
```
pip install -r requirements.txt 
```
Windows:

install [Apple-Devices](https://apps.microsoft.com/detail/9np83lwlpz9k?hl)

<br />

## Usage

Connect an Apple device (iPhone, iPad) to your workstation, unlock and pair the device.
Start the script:
```
python ufade.py
```
or
```
python ufade_gui.py
```

Possibly the trust-message is shown on the device screen. Confirm with "trust".
Now you should see the device information screen and will be prompted to choose a working directory.
By default, the script is setting this to the directory from which it has been called.

In the main menu you have the options:

**Save device information to text**

Save device information and a list of user-installed apps to a textfile.

**Backup Options**

including:

>***Logical (iTunes-Style) Backup***
> 
>*Perform a backup as iTunes would do (with an option to bruteforce an unknown backup-password)*
>  
>***Logical+ Backup***
>  
>*Perform and decrypt an iTunes backup, gather AFC-media files, shared App folders and crash reports. Creates a TAR-archive.*
>  
>***Logical+ Backup (UFED-Style)***
>  
>*Creates an "advanced Logical Backup" as ZIP-archive with an UFD file to load in the [Cellebrite Physical Analyzer©](https://cellebrite.com/de/cellebrite-physical-analyzer-de/)*
>  
>***Filesystem Backup (jailbroken)***
>  
>*Creates a full filesystem backup from an already jailbroken device.*

**Collect Unified Logs**

*Collects the AUL from the device and saves them as a logarchive.*

**Developer Options**

*Try to mount a suitable DeveloperDiskImage. Gives further options for screenshots and filesystem views.* 



<br />

Like this tool? 

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/I3I3H646F)

## Acknowledgements

This script utilizes the following projects:

[pymobiledevice3](https://github.com/doronz88/pymobiledevice3) by [doronz88](https://github.com/doronz88)

[iOSbackup](https://github.com/avibrazil/iOSbackup) by [avibrazil](https://github.com/avibrazil)

[pyiosbackup](https://github.com/matan1008/pyiosbackup) by [matan1008](https://github.com/matan1008)

[pythondialog](https://github.com/frougon/pythondialog) by [frougon](https://github.com/frougon) 

[CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) by [TomSchimansky](https://github.com/TomSchimansky) 

[crossfiledialog](https://github.com/maikelwever/crossfiledialog) by [maikelwever](https://github.com/maikelwever)

[paramiko](https://github.com/paramiko/paramiko), [pandas](https://github.com/pandas-dev/pandas), [pyarrow](https://github.com/apache/arrow), [playsound](https://github.com/TaylorSMarks/playsound) 


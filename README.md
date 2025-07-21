# UFADE
**Universal Forensic Apple Device Extractor**

This is a python script written for my masters thesis in IT-Security and Forensics at the [Wismar University](https://www.hs-wismar.de/).

It utilizes the awesome projects: [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) and [iOSbackup](https://github.com/avibrazil/iOSbackup) to automate the acquisition of Apple mobile devices. Options can be selected via a dialog. The SSH access is realized via [Paramiko](https://github.com/paramiko/paramiko).

The interface is based on [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter). You can also load the Windows version from the release page. 

Requires Python == 3.11.

More features may follow.

UFADE has been selected as a finalist for the [Sans Difference Makers Award 2024](https://www.sans.org/about/awards/difference-makers/) in the category “Innovation of the Year (Open-Source or Product Tool)”.

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

**Install dependencies:**

Arch / Manjaro:
```
sudo pacman -S tk
```
Debian / Ubuntu:
```
sudo apt-get install python3-tk libasound2-dev
```
CentOS / Red Hat:
```
sudo yum install tkinter
```
MacOS:
```
brew install python@3.11 python-tk@3.11
```

**Install the requirements:**
```
pip install -r requirements.txt 
```
Windows:

install [Apple-Devices](https://apps.microsoft.com/detail/9np83lwlpz9k?hl)

Highly recommended: Disable the [Maximum Path Length Limitation](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=Registry) 


<br />

**Venv:**

If you run UFADE in a virtual environment, install: libcairo2 and girepository/libgirepository. Then:
```
pip install pygobject
```

<br />

## Usage

Connect an Apple device (iPhone, iPad) to your workstation, unlock and pair the device.
Start the script:
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
>***PRFS Backup***
>  
>*Perform and decrypt an iTunes backup, gather AFC-media files, shared App folders and crash reports. Creates a TAR-archive structured like the filesystem on the device.*
>    
>***Filesystem Backup (jailbroken)***
>  
>*Creates a full filesystem backup from an already jailbroken device.*

**Collect Unified Logs**

*Collects the AUL from the device and saves them as a logarchive.*

**Developer Options**

*Try to mount a suitable DeveloperDiskImage. Gives further options for screenshots and filesystem views.* 

**Advanced Options**

*Gives options like network-sniffing and various Logging functions .* 



<br />

Like this tool? 

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/I3I3H646F)

## Acknowledgements

This script utilizes the following projects:

[pymobiledevice3](https://github.com/doronz88/pymobiledevice3) by [doronz88](https://github.com/doronz88)

[iOSbackup](https://github.com/avibrazil/iOSbackup) by [avibrazil](https://github.com/avibrazil)

[pyiosbackup](https://github.com/matan1008/pyiosbackup) by [matan1008](https://github.com/matan1008)

[CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) by [TomSchimansky](https://github.com/TomSchimansky) 

[crossfiledialog](https://github.com/maikelwever/crossfiledialog) by [maikelwever](https://github.com/maikelwever)

[paramiko](https://github.com/paramiko/paramiko), [pandas](https://github.com/pandas-dev/pandas), [pyarrow](https://github.com/apache/arrow), [simpleaudio](https://github.com/hamiltron/py-simple-audio), [pdfme](https://github.com/aFelipeSP/pdfme)


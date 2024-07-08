from pymobiledevice3 import usbmux, exceptions, lockdown
from pymobiledevice3.services.mobile_image_mounter import DeveloperDiskImageMounter, MobileImageMounterService, PersonalizedImageMounter
from pymobiledevice3.lockdown import create_using_usbmux, create_using_remote
from pymobiledevice3.lockdown import LockdownClient 
import os



lockdown = create_using_usbmux()
DeveloperDiskImageMounter(lockdown).mount(image=os.path.join(os.path.dirname(__file__),"ufade_developer", "Developer", "14.4", "DeveloperDiskImage.dmg"), signature=os.path.join(os.path.dirname(__file__), "ufade_developer", "Developer", "14.4", "DeveloperDiskImage.dmg.signature"))
                
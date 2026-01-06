import struct
import os
import sys
import textwrap
from importlib import import_module
import pprint
import tempfile
import sqlite3
import time
import mmap
import logging
from datetime import datetime, timezone
from pathlib import Path
from iOSbackup import iOSbackup

# import biplist # binary only
import plistlib # plain text only
import NSKeyedUnArchiver

try:
    from Cryptodome.Cipher import AES
except:
    from Crypto.Cipher import AES # https://www.dlitz.net/software/pycrypto/

module_logger = logging.getLogger(__name__)


# Patch for iOSBackup
def getFileDecryptedCopy(self, relativePath=None, manifestEntry=None,
                                     targetName=None, targetFolder=None, temporary=False):
    """Same as original getFileDecryptedCopy, but skips outFile.truncate"""
    
    if relativePath:
        manifestEntry=self.getFileManifestDBEntry(relativePath=relativePath)

    if manifestEntry:
        info=iOSbackup.getFileInfo(manifestEntry['manifest'])
        fileNameHash=manifestEntry['fileID']
        domain=manifestEntry['domain']
        relativePath=manifestEntry['relativePath']
    else:
        return None

    fileData=info['completeManifest']

    if targetName:
        fileName=targetName
    else:
        fileName='{domain}~{modifiedPath}'.format(domain=domain, modifiedPath=relativePath.replace('/','--'))

    if temporary:
        targetFileName=tempfile.NamedTemporaryFile(suffix=f"---{fileName}", dir=targetFolder, delete=True)
        targetFileName=targetFileName.name
    else:
        if targetFolder:
            targetFileName=os.path.join(targetFolder, fileName)
        else:
            targetFileName=fileName

    if 'EncryptionKey' in fileData:
        encryptionKey=fileData['EncryptionKey'][4:]
        key = self.unwrapKeyForClass(fileData['ProtectionClass'], encryptionKey)

        chunkSize=16*1000000 # 16MB chunk size
        decryptor = AES.new(key, AES.MODE_CBC, b'\x00'*16)

        with open(os.path.join(self.backupRoot, self.udid, fileNameHash[:2], fileNameHash), 'rb') as inFile:
            if os.name == 'nt':
                mappedInFile = mmap.mmap(inFile.fileno(), length=0, access=mmap.ACCESS_READ)
            else:
                mappedInFile = mmap.mmap(inFile.fileno(), length=0, prot=mmap.PROT_READ)

            with open(targetFileName, 'wb') as outFile:
                chunkIndex=0
                while True:
                    chunk = mappedInFile[chunkIndex*chunkSize:(chunkIndex+1)*chunkSize]
                    if len(chunk) == 0:
                        break
                    outFile.write(decryptor.decrypt(chunk))
                    chunkIndex+=1

    elif info['isFolder']:
        Path(targetFileName).mkdir(parents=True, exist_ok=True)
    else:
        shutil.copyfile(
            src=os.path.join(self.backupRoot, self.udid, fileNameHash[:2], fileNameHash),
            dst=targetFileName,
            follow_symlinks=True
        )
        
    mtime=time.mktime(info['lastModified'].astimezone(tz=None).timetuple())
    os.utime(targetFileName,(mtime, mtime))

    info['decryptedFilePath']=targetFileName
    return info


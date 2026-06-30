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

def getFileManifestDBEntry_uf(self, fileNameHash=None, relativePath=None):
        """Modified from iOSbackup"""
        if fileNameHash==None and relativePath==None:
            raise Exception(f"Either fileNameHash or relativePath must be provided")

        if not self.manifestDB:
            raise Exception("Object not yet innitialized or can't find decrypted files catalog ({})".format(iOSbackup.catalog['manifestDB']))

        catalog = sqlite3.connect(self.manifestDB)
        catalog.row_factory=sqlite3.Row

        if relativePath:
            backupFile = catalog.cursor().execute("SELECT * FROM Files WHERE relativePath=? ORDER BY domain LIMIT 1", (relativePath,)).fetchone()
        else:
            backupFile = catalog.cursor().execute("SELECT * FROM Files WHERE fileID=? ORDER BY domain LIMIT 1", (fileNameHash,)).fetchone()

        catalog.close()

        if backupFile:
            payload=dict(backupFile)
            payload['manifest']=NSKeyedUnArchiver.unserializeNSKeyedArchiver(payload['file'])
            del payload['file']
        else:
            if relativePath:
                raise(FileNotFoundError(f"Can't find backup entry for relative path «{relativePath}» on catalog"))
            else:
                raise(FileNotFoundError(f"Can't find backup entry for «{fileNameHash}» on catalog"))

        return payload


def getFileDecryptedCopy(self, relativePath=None, manifestEntry=None,
                                     targetName=None, targetFolder=None, temporary=False):
    """Same as original getFileDecryptedCopy, but skips outFile.truncate"""
    
    if relativePath:
        manifestEntry=getFileManifestDBEntry_uf(self, relativePath=relativePath)

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

                written_size = outFile.tell()
                do_truncate = True

                if written_size > info['size']:
                    with open(targetFileName, "rb") as f:
                        header = f.read(32)

                    if header.startswith(b"SQLite format 3"):
                        do_truncate = False

                    elif header[:4] in (b"\x82\x15\x02\x13", b"\x37\x7f\x06\x82"):
                        do_truncate = False

                    elif b"leveldb" in header.lower():
                        do_truncate = False

                if do_truncate:
                    outFile.truncate(info['size'])

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


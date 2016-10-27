#!/usr/bin/env python3

import ctypes
import fcntl
import string
import os
import time

# ATA Commands
ATA_IDENTIFY = 0xEC
ATA_READ_SECTORS = 0x20
ATA_READ_SECTORS_EXT = 0x24
ATA_READ_VERIFY_SECTORS = 0x40
ATA_READ_VERIFY_SECTORS_EXT = 0x42
ATA_WRITE_SECTORS = 0x30
ATA_WRITE_SECTORS_EXT = 0x34
ATA_SMART_COMMAND = 0xB0
SMART_READ_VALUES = 0xD0
SMART_READ_THRESHOLDS = 0xD1
SMART_RETURN_STATUS = 0xDA
SMART_READ_LOG = 0xD5
SMART_EXECUTE_OFFLINE_IMMEDIATE = 0xD4

SMART_LBA = 0xC24F00
SMART_BAD_STATUS = 0x2CF4

SECURITY_SET_PASSWORD = 0xF1
SECURITY_UNLOCK = 0xF2
SECURITY_ERASE_PREPARE = 0xF3
SECURITY_ERASE_UNIT = 0xF4
SECURITY_FREEZE_LOCK = 0xF5
SECURITY_DISABLE_PASSWORD = 0xF6

# scsi/sg.h
SG_DXFER_NONE = -1          # SCSI Test Unit Ready command
SG_DXFER_TO_DEV = -2        # SCSI WRITE command
SG_DXFER_FROM_DEV = -3      # SCSI READ command

ASCII_S = 83
SG_IO = 0x2285

SPC_SK_ILLEGAL_REQUEST = 0x5


class ataCmd(ctypes.Structure):
    """
    This structure descdibed in http://www.t10.org/ftp/t10/document.04/04-262r8.pdf
    """
    _pack_ = 1
    _fields_ = [
        ('opcode', ctypes.c_ubyte),
        ('protocol', ctypes.c_ubyte),
        ('flags', ctypes.c_ubyte),
        ('features', ctypes.c_ushort),
        ('sector_count', ctypes.c_ushort),
        ('lba_h_low', ctypes.c_ubyte),
        ('lba_low', ctypes.c_ubyte),
        ('lba_h_mid', ctypes.c_ubyte),
        ('lba_mid', ctypes.c_ubyte),
        ('lba_h_high', ctypes.c_ubyte),
        ('lba_high', ctypes.c_ubyte),
        ('device', ctypes.c_ubyte),
        ('command', ctypes.c_ubyte),
        ('control', ctypes.c_ubyte)]


class sgioHdr(ctypes.Structure):
    """
    This structure descibed in scsi/sg.h
    """
    _pack_ = 1
    _fields_ = [
        ('interface_id', ctypes.c_int),
        ('dxfer_direction', ctypes.c_int),
        ('cmd_len', ctypes.c_ubyte),
        ('mx_sb_len', ctypes.c_ubyte),
        ('iovec_count', ctypes.c_ushort),
        ('dxfer_len', ctypes.c_uint),
        ('dxferp', ctypes.c_void_p),
        ('cmdp', ctypes.c_void_p),
        ('sbp', ctypes.c_void_p),
        ('timeout', ctypes.c_uint),
        ('flags', ctypes.c_uint),
        ('pack_id', ctypes.c_int),
        ('usr_ptr', ctypes.c_void_p),
        ('status', ctypes.c_ubyte),
        ('masked_status', ctypes.c_ubyte),
        ('msg_status', ctypes.c_ubyte),
        ('sb_len_wr', ctypes.c_ubyte),
        ('host_status', ctypes.c_ushort),
        ('driver_status', ctypes.c_ushort),
        ('resid', ctypes.c_int),
        ('duration', ctypes.c_uint),
        ('info', ctypes.c_uint)]


class ataptError(Exception):
    """
    Indicates exceptions raised by a atapt class.
    """
    pass


class initFalied(ataptError):
    """
    Raised on atapt initialization falied
    """

    def __init__(self, error):
        ataptError.__init__(
            self, "ATA Pass-Through initialisation falied! reason: " + error)


class sgioFalied(ataptError):
    """
    Raised on SGIO prepare falied
    """

    def __init__(self, error):
        ataptError.__init__(self, "SGIO prepare falied! reason: " + error)


class senseError(ataptError):
    """
    Raised on checkSense found error
    """

    def __init__(self, error):
        ataptError.__init__(self, "Sense check error! reason: " + error)


class securityError(ataptError):
    """
    Raised on security command error
    """

    def __init__(self):
        ataptError.__init__(self, "Security command error!")


def swap16(x):
    return ((x << 8) & 0xFF00) | ((x >> 8) & 0x00FF)


def swapString(strg):
    s = []
    for x in range(0, len(strg) - 1, 2):
        s.append(chr(strg[x + 1]))
        s.append(chr(strg[x]))
    return ''.join(s).strip()


def printBuf(buf):
    """
    Print buf xxd like style
    """
    if buf is None:
        raise ataptError("Got None instead buffer")
    for l in range(0, int(ctypes.sizeof(buf) / 16)):
        intbuf = []
        for i in range(0, 16):
            intbuf.append(
                chr(int.from_bytes(buf[16 * l + i], byteorder='little')))
        buf2 = [('%02x' % ord(i)) for i in intbuf]
        print('{0}: {1:<39}  {2}'.format(('%07x' % (l * 16)),
                                         ' '.join([''.join(buf2[i:i + 2])
                                                   for i in range(0, len(buf2), 2)]),
                                         ''.join([c if c in string.printable[:-5] else '.' for c in intbuf])))


class atapt:
    """
    Main ATA Pass-Through class
    """

    def __init__(self, dev):
        self.smart = {}
        self.ssd = 0
        self.duration = 0
        self.timeout = 1000  # in milliseconds
        self.readCommand = ATA_READ_SECTORS
        self.verifyCommand = ATA_READ_VERIFY_SECTORS
        self.writeCommand = ATA_WRITE_SECTORS
        self.sense = ctypes.c_buffer(64)
        self.checkExists(dev)
        self.devIdentify()

    def checkSense(self):
        response_code = 0x7f & int.from_bytes(
            self.sense[0], byteorder='little')
        if response_code >= 0x72:
            sense_key = 0xf & int.from_bytes(self.sense[1], byteorder='little')
            asc = self.sense[2]
            ascq = self.sense[3]
        else:
            raise senseError("No sense")
        if sense_key == SPC_SK_ILLEGAL_REQUEST:
            if asc == b'\x20' and ascq == b'\x00':
                raise senseError("ATA PASS-THROUGH not supported")
            else:
                raise senseError("Bad field in cdb")
        else:
            if self.sense[8] == b'\x09':
                self.ata_error = int.from_bytes(
                    self.sense[11], byteorder='little')
                self.ata_status = int.from_bytes(
                    self.sense[21], byteorder='little')

    def clearSense(self):
        for i in range(64):
            self.sense[i] = 0

    def prepareSgio(self, cmd, feature, count, lba, direction, buf):
        if direction in [SG_DXFER_FROM_DEV, SG_DXFER_TO_DEV]:
            if buf is None:
                raise sgioFalied("Got None instead buffer")
            buf_len = ctypes.sizeof(buf)
            buf_p = ctypes.cast(buf, ctypes.c_void_p)
            if direction == SG_DXFER_FROM_DEV:
                prot = 4 << 1  # PIO Data-In
            if direction == SG_DXFER_TO_DEV:
                prot = 5 << 1  # PIO Data-Out
        elif direction == SG_DXFER_NONE:
            buf_len = 0
            buf_p = None
            prot = 3 << 1  # Non-data
        else:
            raise sgioFalied("Unknown direction : 0x%0.2X" % direction)

        # raise sgioFalied("Unknown ATA command : 0x%0.2X" % cmd)
        if cmd in [ATA_READ_SECTORS_EXT, ATA_WRITE_SECTORS_EXT, ATA_READ_VERIFY_SECTORS_EXT]:
            prot = prot | 1  # + EXTEND
        sector_lba = lba.to_bytes(6, byteorder='little')
        ata_cmd = ataCmd(opcode=0x85,  # ATA PASS-THROUGH (16)
                         protocol=prot,
                         # flags field
                         # OFF_LINE = 0 (0 seconds offline)
                         # CK_COND = 1 (copy sense data in response)
                         # T_DIR = 1 (transfer from the ATA device)
                         # BYT_BLOK = 1 (length is in blocks, not bytes)
                         # T_LENGTH = 2 (transfer length in the SECTOR_COUNT
                         # field)
                         flags=0x2e,
                         features=swap16(feature),
                         sector_count=swap16(count),
                         lba_h_low=sector_lba[3], lba_low=sector_lba[0],
                         lba_h_mid=sector_lba[4], lba_mid=sector_lba[1],
                         lba_h_high=sector_lba[5], lba_high=sector_lba[2],
                         device=1 << 6,  # Enable LBA on ATA-5 and older drives
                         command=cmd,
                         control=0)

        sgio = sgioHdr(interface_id=ASCII_S, dxfer_direction=direction,
                       cmd_len=ctypes.sizeof(ata_cmd),
                       mx_sb_len=ctypes.sizeof(self.sense), iovec_count=0,
                       dxfer_len=buf_len,
                       dxferp=buf_p,
                       cmdp=ctypes.addressof(ata_cmd),
                       sbp=ctypes.cast(self.sense, ctypes.c_void_p), timeout=self.timeout,
                       flags=0, pack_id=0, usr_ptr=None, status=0, masked_status=0,
                       msg_status=0, sb_len_wr=0, host_status=0, driver_status=0,
                       resid=0, duration=0, info=0)

        return sgio

    def checkExists(self, dev):
        if not os.path.exists(dev):
            raise initFalied("Device not exists")
        self.dev = dev

    def devIdentify(self):
        buf = ctypes.c_buffer(512)
        sgio = self.prepareSgio(ATA_IDENTIFY, 0, 0, 0, SG_DXFER_FROM_DEV, buf)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        self.checkSense()
        self.serial = swapString(buf[20:40])
        self.firmware = swapString(buf[46:53])
        self.model = swapString(buf[54:93])
        self.sectors = int.from_bytes(buf[200] + buf[201] + buf[202] + buf[203] +
                                      buf[204] + buf[205] + buf[206] + buf[207], byteorder='little')
        self.size = self.sectors / 2097152
        self.rpm = int.from_bytes(buf[434] + buf[435], byteorder='little')
        if self.rpm == 1:
            self.ssd = 1

        # word 168 bits 0-3 "Device form factor"
        fFactor = int.from_bytes(buf[336] + buf[337], byteorder='little') & 0xF
        if fFactor == 0:
            self.formFactor = ""
        elif fFactor == 1:
            self.formFactor = "5.25"
        elif fFactor == 2:
            self.formFactor = "3.5"
        elif fFactor == 3:
            self.formFactor = "2.5"
        elif fFactor == 4:
            self.formFactor = "1.8"
        elif fFactor == 5:
            self.formFactor = "less than 1.8"
        elif fFactor > 5:
            self.formFactor = ""

         # word 106 bit 12 "Device Logical Sector longer than 256 Words"
        if not int.from_bytes(buf[212] + buf[213], byteorder='little') & 0x1000:
            self.logicalSectorSize = 512
        else:
            self.logicalSectorSize = int.from_bytes(buf[234] + buf[235] + buf[236] + buf[237], byteorder='little')

        # word 106 bit 13 "Device has multiple logical sectors per physical sector"
        if not int.from_bytes(buf[212] + buf[213], byteorder='little') & 0x2000:
            self.physicalSectorSize = self.logicalSectorSize
        else:
            self.physicalSectorSize = (1 << (int.from_bytes(
                buf[212] + buf[213], byteorder='little') & 0x0F)) * self.logicalSectorSize

        # word 80 "ATA Major version number"
        major = int.from_bytes(buf[160] + buf[161], byteorder='little')
        if major & 0x800:
            self.ataMajor = "ACS-4"
        elif major & 0x400:
            self.ataMajor = "ACS-3"
        elif major & 0x200:
            self.ataMajor = "ACS-2"
        elif major & 0x100:
            self.ataMajor = "ATA8-ACS"
        elif major & 0x80:
            self.ataMajor = "ATA/ATAPI-7"
        elif major & 0x40:
            self.ataMajor = "ATA/ATAPI-6"
        elif major & 0x20:
            self.ataMajor = "ATA/ATAPI-5"
        else:
            self.ataMajor = ""

        # word 81 "ATA Minor version number"
        minor = int.from_bytes(buf[162] + buf[163], byteorder='little')
        if minor == 0x13:
            self.ataMinor = "T13 1321D version 3"
        elif minor == 0x15:
            self.ataMinor = "T13 1321D version 1"
        elif minor == 0x16:
            self.ataMinor = "published, ANSI INCITS 340-2000"
        elif minor == 0x18:
            self.ataMinor = "T13 1410D version 0"
        elif minor == 0x19:
            self.ataMinor = "T13 1410D version 3a"
        elif minor == 0x1A:
            self.ataMinor = "T13 1532D version 1"
        elif minor == 0x1B:
            self.ataMinor = "T13 1410D version 2"
        elif minor == 0x1C:
            self.ataMinor = "T13 1410D version 1"
        elif minor == 0x1D:
            self.ataMinor = "published, ANSI INCITS 397-2005"
        elif minor == 0x1E:
            self.ataMinor = "T13 1532D version 0"
        elif minor == 0x1F:
            self.ataMinor = "T13/2161-D version 3b"
        elif minor == 0x21:
            self.ataMinor = "T13 1532D version 4a"
        elif minor == 0x22:
            self.ataMinor = "published, ANSI INCITS 361-2002"
        elif minor == 0x27:
            self.ataMinor = "T13/1699-D version 3c"
        elif minor == 0x28:
            self.ataMinor = "T13/1699-D version 6"
        elif minor == 0x29:
            self.ataMinor = "T13/1699-D version 4"
        elif minor == 0x31:
            self.ataMinor = "T13/2015-D Revision 2"
        elif minor == 0x33:
            self.ataMinor = "T13/1699-D version 3e"
        elif minor == 0x39:
            self.ataMinor = "T13/1699-D version 4c"
        elif minor == 0x42:
            self.ataMinor = "T13/1699-D version 3f"
        elif minor == 0x52:
            self.ataMinor = "T13/1699-D version 3b"
        elif minor == 0x5E:
            self.ataMinor = "T13/BSR INCITS 529 revision 5"
        elif minor == 0x6D:
            self.ataMinor = "T13/2161-D revision 5"
        elif minor == 0x82:
            self.ataMinor = "published, ANSI INCITS 482-2012"
        elif minor == 0x107:
            self.ataMinor = "T13/1699-D version 2a"
        elif minor == 0x10A:
            self.ataMinor = "published, ANSI INCITS 522-2014"
        elif minor == 0x110:
            self.ataMinor = "T13/2015-D Revision 3"
        elif minor == 0x11b:
            self.ataMinor = "T13/2015-D Revision 4"
        else:
            self.ataMinor = ""

        # word 222 "Transport major version number"
        major = int.from_bytes(buf[444] + buf[445], byteorder='little')
        if major & 0x40:
            self.transport = "SATA 3.1"
        elif major & 0x20:
            self.transport = "SATA 3.0"
        elif major & 0x10:
            self.transport = "SATA 2.6"
        elif major & 0x8:
            self.transport = "SATA 2.5"
        elif major & 0x4:
            self.transport = "SATA II Extensions"
        elif major & 0x2:
            self.transport = "SATA 1.0a"
        elif major & 0x1:
            self.transport = "ATA8-AST"
        else:
            self.transport = ""

        # word 76 "Serial ATA capabilities"
        cap = int.from_bytes(buf[152] + buf[153], byteorder='little')
        if cap & 0x800:
            self.sataGen = "Gen.3 (6.0Gb/s)"
        elif cap & 0x400:
            self.sataGen = "Gen.2 (3.0Gb/s)"
        elif cap & 0x200:
            self.sataGen = "Gen.1 (1.5Gb/s)"
        else:
            self.sataGen = ""

        # word 83 "Commands and feature sets supported"
        features = int.from_bytes(buf[166] + buf[167], byteorder='little')
        if features & 0x400:
            self.lba48bit = True
        else:
            self.lba48bit = False

        if self.lba48bit:
            self.readCommand = ATA_READ_SECTORS_EXT
            self.verifyCommand = ATA_READ_VERIFY_SECTORS_EXT
            self.writeCommand = ATA_WRITE_SECTORS_EXT

        # word 82 "Commands and feature sets supported"
        features = int.from_bytes(buf[164] + buf[165], byteorder='little')
        if features & 0x2:
            self.security = True
            # word 89 "Time required for a Normal Erase mode"
            self.normalEraseTimeout = int.from_bytes(buf[178] + buf[179], byteorder='little') * 2
        else:
            self.security = False

        if self.security:
            securityStatus = int.from_bytes(buf[256] + buf[257], byteorder='little')
            if securityStatus & 0x2:
                self.securityEnabled = True
            else:
                self.securityEnabled = False

            if securityStatus & 0x4:
                self.securityLocked = True
            else:
                self.securityLocked = False

            if securityStatus & 0x8:
                self.securityFrozen = True
            else:
                self.securityFrozen = False

            if securityStatus & 0x10:
                self.securityExpired = True
            else:
                self.securityExpired = False

            if securityStatus & 0x20:
                self.securityEnhancedErase = True
                # word 90 "Time required for a Enhanced Erase mode"
                self.enhancedEraseTimeout = int.from_bytes(buf[178] + buf[179], byteorder='little') * 2
            else:
                self.securityEnhancedErase = False

            self.securityMasterPwdCap = securityStatus & 0x100

    def readSectors(self, count, start):
        buf = ctypes.c_buffer(count * self.logicalSectorSize)
        sgio = self.prepareSgio(self.readCommand, 0, count, start, SG_DXFER_FROM_DEV, buf)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        self.checkSense()
        return buf

    def verifySectors(self, count, start):
        sgio = self.prepareSgio(self.verifyCommand, 0, count, start, SG_DXFER_NONE, None)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        self.checkSense()

    def writeSectors(self, count, start, buf):
        sgio = self.prepareSgio(self.writeCommand, 0, count, start, SG_DXFER_TO_DEV, buf)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        self.checkSense()

    def readSmartValues(self):
        buf = ctypes.c_buffer(512)
        sgio = self.prepareSgio(ATA_SMART_COMMAND, SMART_READ_VALUES, 1, SMART_LBA, SG_DXFER_FROM_DEV, buf)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        self.checkSense()
        return buf

    def readSmartThresholds(self):
        buf = ctypes.c_buffer(512)
        sgio = self.prepareSgio(ATA_SMART_COMMAND, SMART_READ_THRESHOLDS, 1, SMART_LBA, SG_DXFER_FROM_DEV, buf)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        self.checkSense()
        return buf

    def readSmart(self):
        buf = ctypes.c_buffer(512)
        buf = self.readSmartValues()
        self.selftestStatus = int.from_bytes(buf[363], byteorder='little')
        self.smart = {}
        for i in range(30):
            if buf[2 + i * 12] == b'\x00':
                continue
            aid = int.from_bytes(buf[2 + i * 12], byteorder='little')
            pre_fail = int.from_bytes(buf[2 + i * 12 + 1], byteorder='little') & 1
            online = (int.from_bytes(buf[2 + i * 12 + 1], byteorder='little') & 2) >> 1
            current = int.from_bytes(buf[2 + i * 12 + 3], byteorder='little')
            if current == 0 or current == 0xfe or current == 0xff:
                continue
            worst = int.from_bytes(buf[2 + i * 12 + 4], byteorder='little')
            raw = int.from_bytes(buf[2 + i * 12 + 5] + buf[2 + i * 12 + 6] + buf[2 + i * 12 + 7] +
                                 buf[2 + i * 12 + 8] + buf[2 + i * 12 + 9] + buf[2 + i * 12 + 10], byteorder='little')
            self.smart[aid] = [pre_fail, online, current, worst, raw]
        buf = self.readSmartThresholds()
        for i in range(30):
            if buf[2 + i * 12] == b'\x00':
                continue
            aid = int.from_bytes(buf[2 + i * 12], byteorder='little')
            if aid in self.smart:
                self.smart[aid].append(int.from_bytes(buf[2 + i * 12 + 1], byteorder='little'))

    def getSmartStr(self, id):
        if id == 1:
            return "Raw_Read_Error_Rate"
        elif id == 2:
            return "Throughput_Performance"
        elif id == 3:
            return "Spin_Up_Time"
        elif id == 4:
            return "Start_Stop_Count"
        elif id == 5:
            return "Reallocated_Sector_Ct"
        elif id == 6:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Read_Channel_Margin"
        elif id == 7:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Seek_Error_Rate"
        elif id == 8:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Seek_Time_Performance"
        elif id == 9:
            return "Power_On_Hours"
        elif id == 10:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Spin_Retry_Count"
        elif id == 11:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Calibration_Retry_Count"
        elif id == 12:
            return "Power_Cycle_Count"
        elif id == 13:
            return "Read_Soft_Error_Rate"
        elif id == 170:
            if self.ssd:
                return "Reserve_Block_Count"
        elif id == 171:
            if self.ssd:
                return "Program_Fail_Count"
        elif id == 172:
            if self.ssd:
                return "Erase_Fail_Count"
        elif id == 174:
            if self.ssd:
                return "Unexpected_Power_Loss"
        elif id == 175:
            if not self.ssd:
                return "Unknown_HDD_Attribute"
            return "Program_Fail_Count_Chip"
        elif id == 176:
            if not self.ssd:
                return "Unknown_HDD_Attribute"
            return "Erase_Fail_Count_Chip"
        elif id == 177:
            if not self.ssd:
                return "Unknown_HDD_Attribute"
            return "Wear_Leveling_Count"
        elif id == 178:
            if not self.ssd:
                return "Unknown_HDD_Attribute"
            return "Used_Rsvd_Blk_Cnt_Chip"
        elif id == 179:
            if not self.ssd:
                return "Unknown_HDD_Attribute"
            return "Used_Rsvd_Blk_Cnt_Tot"
        elif id == 180:
            if not self.ssd:
                return "Unknown_HDD_Attribute"
            return "Unused_Rsvd_Blk_Cnt_Tot"
        elif id == 181:
            return "Program_Fail_Cnt_Total"
        elif id == 182:
            if not self.ssd:
                return "Unknown_HDD_Attribute"
            return "Erase_Fail_Count_Total"
        elif id == 183:
            return "Runtime_Bad_Block"
        elif id == 184:
            return "End-to-End_Error"
        elif id == 187:
            return "Reported_Uncorrect"
        elif id == 188:
            return "Command_Timeout"
        elif id == 189:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "High_Fly_Writes"
        elif id == 190:
            return "Airflow_Temperature_Cel"
        elif id == 191:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "G-Sense_Error_Rate"
        elif id == 192:
            return "Power-Off_Retract_Count"
        elif id == 193:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Load_Cycle_Count"
        elif id == 194:
            return "Temperature_Celsius"
        elif id == 195:
            return "Hardware_ECC_Recovered"
        elif id == 196:
            return "Reallocated_Event_Count"
        elif id == 197:
            return "Current_Pending_Sector"
        elif id == 198:
            return "Offline_Uncorrectable"
        elif id == 199:
            return "UDMA_CRC_Error_Count"
        elif id == 200:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Multi_Zone_Error_Rate"
        elif id == 201:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Soft_Read_Error_Rate"
        elif id == 202:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Data_Address_Mark_Errs"
        elif id == 203:
            return "Run_Out_Cancel"
        elif id == 204:
            return "Soft_ECC_Correction"
        elif id == 205:
            return "Thermal_Asperity_Rate"
        elif id == 206:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Flying_Height"
        elif id == 207:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Spin_High_Current"
        elif id == 208:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Spin_Buzz"
        elif id == 209:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Offline_Seek_Performnce"
        elif id == 220:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Disk_Shift"
        elif id == 221:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "G-Sense_Error_Rate"
        elif id == 222:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Loaded_Hours"
        elif id == 223:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Load_Retry_Count"
        elif id == 224:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Load_Friction"
        elif id == 225:
            if self.ssd:
                return "Host_Writes"
            return "Load_Cycle_Count"
        elif id == 226:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Load-in_Time"
        elif id == 227:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Torq-amp_Count"
        elif id == 228:
            return "Power-off_Retract_Count"
        elif id == 230:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Head_Amplitude"
        elif id == 231:
            if self.ssd:
                return "SSD Life Left"
            return "Temperature_Celsius"
        elif id == 232:
            return "Available_Reservd_Space"
        elif id == 233:
            if not self.ssd:
                return "Unknown_HDD_Attribute"
            return "Media_Wearout_Indicator"
        elif id == 240:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Head_Flying_Hours"
        elif id == 241:
            return "Total_LBAs_Written"
        elif id == 242:
            return "Total_LBAs_Read"
        elif id == 249:
            if self.ssd:
                return "Total_NAND_Writes"
        elif id == 250:
            return "Read_Error_Retry_Rate"
        elif id == 254:
            if self.ssd:
                return "Unknown_SSD_Attribute"
            return "Free_Fall_Sensor"
        else:
            return "Unknown_Attribute"

    def getSmartRawStr(self, id):
        if id == 3:
            return str(self.smart[id][4] & 0xFFFF)
        elif id == 5 or id == 196:
            return str(self.smart[id][4] & 0xFFFF)
        elif id == 9 or id == 240:
            return str(self.smart[id][4] & 0xFFFF)
        elif id == 190 or id == 194:
            return str(self.smart[id][4] & 0xFF)
        else:
            return str(self.smart[id][4])

    def readSmartStatus(self):
        sgio = self.prepareSgio(ATA_SMART_COMMAND, SMART_RETURN_STATUS, 1, SMART_LBA, SG_DXFER_NONE, None)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        self.checkSense()
        status = int.from_bytes(self.sense[17] + self.sense[19], byteorder='little')
        return status

    def readSmartLog(self, logAddress):
        buf = ctypes.c_buffer(512)
        sgio = self.prepareSgio(ATA_SMART_COMMAND, SMART_READ_LOG, 1, SMART_LBA + logAddress, SG_DXFER_FROM_DEV, buf)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        self.checkSense()
        return buf

    def runSmartSelftest(self, subcommand):
        sgio = self.prepareSgio(ATA_SMART_COMMAND, SMART_EXECUTE_OFFLINE_IMMEDIATE, 1, SMART_LBA + subcommand, SG_DXFER_NONE, None)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        self.checkSense()

    def getSelftestLog(self):
        buf = ctypes.c_buffer(512)
        buf = self.readSmartLog(6)
        log = []
        revision = int.from_bytes(buf[0] + buf[1], byteorder='little')
        for i in range(2, 485, 24):
            if buf[i] == b'\x00':
                continue
            if buf[i] == b'\x01':
                test = "Short offline"
            elif buf[i] == b'\x02':
                test = "Extended offline"
            elif buf[i] == b'\x03':
                test = "Conveyance offline"
            elif buf[i] == b'\x04':
                test = "Selective offline"
            elif buf[i] == b'\x81':
                test = "Short captive"
            elif buf[i] == b'\x82':
                test = "Extended captive"
            elif buf[i] == b'\x83':
                test = "Conveyance captive"
            elif buf[i] == b'\x84':
                test = "Selective captive"

            st = int.from_bytes(buf[i + 1], byteorder='little') >> 4
            if st == 0:
                status = "completed"
            elif st == 1:
                status = "aborted by host"
            elif st == 4:
                status = "interrupted by reset"
            elif st == 3:
                status = "fatal error"
            elif st == 2:
                status = "unknoun failure"
            elif st == 5:
                status = "electrical failure"
            elif st == 6:
                status = "servo failure"
            elif st == 7:
                status = "read failure"
            elif st == 8:
                status = "handling damage"
            elif st == 0x0F:
                status = "in progress"

            remaining = int((int.from_bytes(buf[i + 1], byteorder='little') & 0x0F) * 10)
            if remaining == 100:
                remaining = 0

            lifetime = int.from_bytes(buf[i + 2] + buf[i + 3], byteorder='little')
            lba = int.from_bytes(buf[i + 5] + buf[i + 6] + buf[i + 7] + buf[i + 8], byteorder='little')
            log.append((test, status, remaining, lifetime, lba))
        return ((revision, log))

    def securityDisable(self, master, password):
        buf = ctypes.c_buffer(512)
        if master:
            buf[0] = 1
        else:
            buf[0] = 0
        pwd = str.encode(password)
        i = 2
        for b in pwd:
            buf[i] = b
            i = i + 1
        sgio = self.prepareSgio(SECURITY_DISABLE_PASSWORD, 0, 0, 0, SG_DXFER_TO_DEV, buf)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        try:
            self.checkSense()
        except senseError:
            raise securityError()

    def securityUnlock(self, master, password):
        buf = ctypes.c_buffer(512)
        if master:
            buf[0] = 1
        else:
            buf[0] = 0
        pwd = str.encode(password)
        i = 2
        for b in pwd:
            buf[i] = b
            i = i + 1
        sgio = self.prepareSgio(SECURITY_UNLOCK, 0, 0, 0, SG_DXFER_TO_DEV, buf)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        try:
            self.checkSense()
        except senseError:
            raise securityError()

    def securityFreeze(self):
        sgio = self.prepareSgio(SECURITY_FREEZE_LOCK, 0, 0, 0, SG_DXFER_NONE, None)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        try:
            self.checkSense()
        except senseError:
            raise securityError()

    def securityEraseUnit(self, master, enhanced, password):
        buf = ctypes.c_buffer(512)
        if master:
            buf[0] = 1
        else:
            buf[0] = 0
        if enhanced:
            buf[0] = buf[0] + 2
        pwd = str.encode(password)
        i = 2
        for b in pwd:
            buf[i] = b
            i = i + 1
        sgio = self.prepareSgio(SECURITY_ERASE_PREPARE, 0, 0, 0, SG_DXFER_NONE, None)
        with open(self.dev, 'r') as fd:
            try:
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        tempTimeout = self.timeout
        if enhanced:
            self.timeout = self.enhancedEraseTimeout
        else:
            self.timeout = self.normalEraseTimeout
        if self.timeout == 0 or self.timeout == 510:
            self.timeout = 12 * 60 * 60 * 1000  # default timeout twelve hours
        else:
            self.timeout = (self.timeout + 30) * 60 * 1000  # +30min then convert to milliseconds
        sgio = self.prepareSgio(SECURITY_ERASE_UNIT, 0, 0, 0, SG_DXFER_TO_DEV, buf)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.timeout = tempTimeout
        self.duration = (time.time() - startTime) * 1000
        try:
            self.checkSense()
        except senseError:
            raise securityError()

    def securitySetPassword(self, master, capability, password):
        buf = ctypes.c_buffer(512)
        if master:
            buf[0] = 1
        else:
            buf[0] = 0
        if capability:
            buf[1] = 1
        pwd = str.encode(password)
        i = 2
        for b in pwd:
            buf[i] = b
            i = i + 1
        sgio = self.prepareSgio(SECURITY_SET_PASSWORD, 0, 0, 0, SG_DXFER_TO_DEV, buf)
        self.clearSense()
        with open(self.dev, 'r') as fd:
            try:
                startTime = time.time()
                fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio))
            except IOError:
                raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000
        try:
            self.checkSense()
        except senseError:
            raise securityError()



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

libc = ctypes.CDLL('libc.so.6')

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
            buf_p = ctypes.addressof(buf)
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
        self.ata_cmd = ataCmd(opcode=0x85,  # ATA PASS-THROUGH (16)
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

        self.sgio = sgioHdr(interface_id=ASCII_S, dxfer_direction=direction,
                       cmd_len=ctypes.sizeof(self.ata_cmd),
                       mx_sb_len=ctypes.sizeof(self.sense), iovec_count=0,
                       dxfer_len=buf_len,
                       dxferp=buf_p,
                       cmdp=ctypes.addressof(self.ata_cmd),
                       sbp=ctypes.addressof(self.sense), timeout=self.timeout,
                       flags=0, pack_id=0, usr_ptr=None, status=0, masked_status=0,
                       msg_status=0, sb_len_wr=0, host_status=0, driver_status=0,
                       resid=0, duration=0, info=0)

    def doSgio(self):
        fd = os.open(self.dev, os.O_RDWR)
        startTime = time.time()
        if libc.ioctl(fd, SG_IO, ctypes.c_uint64(ctypes.addressof(self.sgio))) != 0:
            raise sgioFalied("fcntl.ioctl falied")
        self.duration = (time.time() - startTime) * 1000

    def checkExists(self, dev):
        if not os.path.exists(dev):
            raise initFalied("Device not exists")
        self.dev = dev

    def devIdentify(self):
        buf = ctypes.c_buffer(512)
        self.prepareSgio(ATA_IDENTIFY, 0, 0, 0, SG_DXFER_FROM_DEV, buf)
        self.clearSense()
        self.doSgio()
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
        self.formFactor = {
                1: "5.25",
                2: "3.5",
                3: "2.5",
                4: "1.8",
                5: "less than 1.8"
        }.get(fFactor, "")

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
        major = int.from_bytes(buf[160] + buf[161], byteorder='little') & 0xFE0
        self.ataMajor = {
                0xFE0: "ACS-4",
                0x7E0: "ACS-3",
                0x3E0: "ACS-2",
                0x1E0: "ATA8-ACS",
                0x0E0: "ATA/ATAPI-7",
                0x060: "ATA/ATAPI-6",
                0x020: "ATA/ATAPI-5"
        }.get(major, "")

        # word 81 "ATA Minor version number"
        minor = int.from_bytes(buf[162] + buf[163], byteorder='little')
        self.ataMinor = {
                0x13: "T13 1321D version 3",
                0x15: "T13 1321D version 1",
                0x16: "published, ANSI INCITS 340-2000",
                0x18: "T13 1410D version 0",
                0x19: "T13 1410D version 3a",
                0x1A: "T13 1532D version 1",
                0x1B: "T13 1410D version 2",
                0x1C: "T13 1410D version 1",
                0x1D: "published, ANSI INCITS 397-2005",
                0x1E: "T13 1532D version 0",
                0x1F: "T13/2161-D version 3b",
                0x21: "T13 1532D version 4a",
                0x22: "published, ANSI INCITS 361-2002",
                0x27: "T13/1699-D version 3c",
                0x28: "T13/1699-D version 6",
                0x29: "T13/1699-D version 4",
                0x31: "T13/2015-D Revision 2",
                0x33: "T13/1699-D version 3e",
                0x39: "T13/1699-D version 4c",
                0x42: "T13/1699-D version 3f",
                0x52: "T13/1699-D version 3b",
                0x5E: "T13/BSR INCITS 529 revision 5",
                0x6D: "T13/2161-D revision 5",
                0x82: "published, ANSI INCITS 482-2012",
                0x107: "T13/1699-D version 2a",
                0x10A: "published, ANSI INCITS 522-2014",
                0x110: "T13/2015-D Revision 3",
                0x11b: "T13/2015-D Revision 4"
        }.get(minor, "")

        # word 222 "Transport major version number"
        major = int.from_bytes(buf[444] + buf[445], byteorder='little') & 0x7E
        self.transport = {
                0x7E: "SATA 3.1",
                0x3E: "SATA 3.0",
                0x1E: "SATA 2.6",
                0x0E: "SATA 2.5",
                0x07: "SATA II Extensions",
                0x03: "SATA 1.0a"
        }.get(major, "")

        # word 76 "Serial ATA capabilities"
        cap = int.from_bytes(buf[152] + buf[153], byteorder='little') & 0xE00
        self.sataGen = {
                0xE00: "Gen.3 (6.0Gb/s)",
                0x600: "Gen.2 (3.0Gb/s)",
                0x200: "Gen.1 (1.5Gb/s)"
        }.get(cap, "")

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
        self.prepareSgio(self.readCommand, 0, count, start, SG_DXFER_FROM_DEV, buf)
        self.clearSense()
        self.doSgio()
        self.checkSense()
        return buf

    def verifySectors(self, count, start):
        self.prepareSgio(self.verifyCommand, 0, count, start, SG_DXFER_NONE, None)
        self.clearSense()
        self.doSgio()
        self.checkSense()

    def writeSectors(self, count, start, buf):
        self.prepareSgio(self.writeCommand, 0, count, start, SG_DXFER_TO_DEV, buf)
        self.clearSense()
        self.doSgio()
        self.checkSense()

    def readSmartValues(self):
        buf = ctypes.c_buffer(512)
        self.prepareSgio(ATA_SMART_COMMAND, SMART_READ_VALUES, 1, SMART_LBA, SG_DXFER_FROM_DEV, buf)
        self.clearSense()
        self.doSgio()
        self.checkSense()
        return buf

    def readSmartThresholds(self):
        buf = ctypes.c_buffer(512)
        self.prepareSgio(ATA_SMART_COMMAND, SMART_READ_THRESHOLDS, 1, SMART_LBA, SG_DXFER_FROM_DEV, buf)
        self.clearSense()
        self.doSgio()
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
        if self.ssd:
            return {  # SSD SMART Attributes
                    1: "Raw_Read_Error_Rate",
                    2: "Throughput_Performance",
                    3: "Spin_Up_Time",
                    4: "Start_Stop_Count",
                    5: "Reallocated_Sector_Ct",
                    9: "Power_On_Hours",
                    12: "Power_Cycle_Count",
                    13: "Read_Soft_Error_Rate",
                    170: "Reserve_Block_Count",
                    171: "Program_Fail_Count",
                    172: "Erase_Fail_Count",
                    174: "Unexpected_Power_Loss",
                    175: "Program_Fail_Count_Chip",
                    176: "Erase_Fail_Count_Chip",
                    177: "Wear_Leveling_Count",
                    178: "Used_Rsvd_Blk_Cnt_Chip",
                    179: "Used_Rsvd_Blk_Cnt_Tot",
                    180: "Unused_Rsvd_Blk_Cnt_Tot",
                    181: "Program_Fail_Cnt_Total",
                    182: "Erase_Fail_Count_Total",
                    183: "Runtime_Bad_Block",
                    184: "End-to-End_Error",
                    187: "Reported_Uncorrect",
                    188: "Command_Timeout",
                    190: "Airflow_Temperature_Cel",
                    192: "Power-Off_Retract_Count",
                    194: "Temperature_Celsius",
                    195: "Hardware_ECC_Recovered",
                    196: "Reallocated_Event_Count",
                    197: "Current_Pending_Sector",
                    198: "Offline_Uncorrectable",
                    199: "UDMA_CRC_Error_Count",
                    203: "Run_Out_Cancel",
                    204: "Soft_ECC_Correction",
                    205: "Thermal_Asperity_Rate",
                    225: "Host_Writes",
                    228: "Power-off_Retract_Count",
                    231: "SSD Life Left",
                    232: "Available_Reservd_Space",
                    233: "Media_Wearout_Indicator",
                    241: "Total_LBAs_Written",
                    242: "Total_LBAs_Read",
                    249: "Total_NAND_Writes",
                    250: "Read_Error_Retry_Rate"
            }.get(id, "Unknown_SSD_Attribute")
        else:
            return {  # HDD SMART Attributes
                    1: "Raw_Read_Error_Rate",
                    2: "Throughput_Performance",
                    3: "Spin_Up_Time",
                    4: "Start_Stop_Count",
                    5: "Reallocated_Sector_Ct",
                    6: "Read_Channel_Margin",
                    7: "Seek_Error_Rate",
                    8: "Seek_Time_Performance",
                    9: "Power_On_Hours",
                    10: "Spin_Retry_Count",
                    11: "Calibration_Retry_Count",
                    12: "Power_Cycle_Count",
                    13: "Read_Soft_Error_Rate",
                    170: "Reserve_Block_Count",
                    181: "Program_Fail_Cnt_Total",
                    183: "Runtime_Bad_Block",
                    184: "End-to-End_Error",
                    187: "Reported_Uncorrect",
                    188: "Command_Timeout",
                    189: "High_Fly_Writes",
                    190: "Airflow_Temperature_Cel",
                    191: "G-Sense_Error_Rate",
                    192: "Power-Off_Retract_Count",
                    193: "Load_Cycle_Count",
                    194: "Temperature_Celsius",
                    195: "Hardware_ECC_Recovered",
                    196: "Reallocated_Event_Count",
                    197: "Current_Pending_Sector",
                    198: "Offline_Uncorrectable",
                    199: "UDMA_CRC_Error_Count",
                    200: "Multi_Zone_Error_Rate",
                    201: "Soft_Read_Error_Rate",
                    202: "Data_Address_Mark_Errs",
                    203: "Run_Out_Cancel",
                    204: "Soft_ECC_Correction",
                    205: "Thermal_Asperity_Rate",
                    206: "Flying_Height",
                    207: "Spin_High_Current",
                    208: "Spin_Buzz",
                    209: "Offline_Seek_Performnce",
                    220: "Disk_Shift",
                    221: "G-Sense_Error_Rate",
                    222: "Loaded_Hours",
                    223: "Load_Retry_Count",
                    224: "Load_Friction",
                    225: "Load_Cycle_Count",
                    226: "Load-in_Time",
                    227: "Torq-amp_Count",
                    228: "Power-off_Retract_Count",
                    230: "Head_Amplitude",
                    231: "Temperature_Celsius",
                    232: "Available_Reservd_Space",
                    233: "Media_Wearout_Indicator",
                    240: "Head_Flying_Hours",
                    241: "Total_LBAs_Written",
                    242: "Total_LBAs_Read",
                    250: "Read_Error_Retry_Rate",
                    254: "Free_Fall_Sensor"
            }.get(id, "Unknown_Attribute")

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
        self.prepareSgio(ATA_SMART_COMMAND, SMART_RETURN_STATUS, 1, SMART_LBA, SG_DXFER_NONE, None)
        self.clearSense()
        self.doSgio()
        self.checkSense()
        status = int.from_bytes(self.sense[17] + self.sense[19], byteorder='little')
        return status

    def readSmartLog(self, logAddress):
        buf = ctypes.c_buffer(512)
        self.prepareSgio(ATA_SMART_COMMAND, SMART_READ_LOG, 1, SMART_LBA + logAddress, SG_DXFER_FROM_DEV, buf)
        self.clearSense()
        self.doSgio()
        self.checkSense()
        return buf

    def runSmartSelftest(self, subcommand):
        self.prepareSgio(ATA_SMART_COMMAND, SMART_EXECUTE_OFFLINE_IMMEDIATE, 1, SMART_LBA + subcommand, SG_DXFER_NONE, None)
        self.clearSense()
        self.doSgio()
        self.checkSense()

    def getSelftestLog(self):
        buf = ctypes.c_buffer(512)
        buf = self.readSmartLog(6)
        log = []
        revision = int.from_bytes(buf[0] + buf[1], byteorder='little')
        for i in range(2, 485, 24):
            if buf[i] == b'\x00':
                continue
            test = {
                    b'\x01': "Short offline",
                    b'\x02': "Extended offline",
                    b'\x03': "Conveyance offline",
                    b'\x04': "Selective offline",
                    b'\x81': "Short captive",
                    b'\x82': "Extended captive",
                    b'\x83': "Conveyance captive",
                    b'\x84': "Selective captive"
            }.get(buf[i])

            st = int.from_bytes(buf[i + 1], byteorder='little') >> 4
            status = {
                    0: "completed",
                    1: "aborted by host",
                    2: "unknoun failure",
                    3: "fatal error",
                    4: "interrupted by reset",
                    5: "electrical failure",
                    6: "servo failure",
                    7: "read failure",
                    8: "handling damage",
                    0x0F: "in progress"
            }.get(st)

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
        self.prepareSgio(SECURITY_DISABLE_PASSWORD, 0, 0, 0, SG_DXFER_TO_DEV, buf)
        self.clearSense()
        self.doSgio()
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
        self.prepareSgio(SECURITY_UNLOCK, 0, 0, 0, SG_DXFER_TO_DEV, buf)
        self.clearSense()
        self.doSgio()
        try:
            self.checkSense()
        except senseError:
            raise securityError()

    def securityFreeze(self):
        self.prepareSgio(SECURITY_FREEZE_LOCK, 0, 0, 0, SG_DXFER_NONE, None)
        self.clearSense()
        self.doSgio()
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
        self.prepareSgio(SECURITY_ERASE_PREPARE, 0, 0, 0, SG_DXFER_NONE, None)
        self.doSgio()
        tempTimeout = self.timeout
        if enhanced:
            self.timeout = self.enhancedEraseTimeout
        else:
            self.timeout = self.normalEraseTimeout
        if self.timeout == 0 or self.timeout == 510:
            self.timeout = 12 * 60 * 60 * 1000  # default timeout twelve hours
        else:
            self.timeout = (self.timeout + 30) * 60 * 1000  # +30min then convert to milliseconds
        self.prepareSgio(SECURITY_ERASE_UNIT, 0, 0, 0, SG_DXFER_TO_DEV, buf)
        self.clearSense()
        self.doSgio()
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
        self.prepareSgio(SECURITY_SET_PASSWORD, 0, 0, 0, SG_DXFER_TO_DEV, buf)
        self.clearSense()
        self.doSgio()
        try:
            self.checkSense()
        except senseError:
            raise securityError()


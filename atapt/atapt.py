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

SMART_LBA = 0xC24F00

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
        self.timeout = 1000
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

    def prepareSgio(self, cmd, feature, count, lba, buf):
        if cmd in [ATA_IDENTIFY, ATA_READ_SECTORS, ATA_READ_SECTORS_EXT, ATA_SMART_COMMAND]:
            if buf is None:
                raise sgioFalied("Got None instead buffer")
            direction = SG_DXFER_FROM_DEV
            buf_len = ctypes.sizeof(buf)
            buf_p = ctypes.cast(buf, ctypes.c_void_p)
            prot = 4 << 1  # PIO Data-In
        elif cmd in [ATA_WRITE_SECTORS, ATA_WRITE_SECTORS_EXT]:
            if buf is None:
                raise sgioFalied("Got None instead buffer")
            direction = SG_DXFER_TO_DEV
            buf_len = ctypes.sizeof(buf)
            buf_p = ctypes.cast(buf, ctypes.c_void_p)
            prot = 5 << 1  # PIO Data-Out
        elif cmd in [ATA_READ_VERIFY_SECTORS, ATA_READ_VERIFY_SECTORS_EXT]:
            direction = SG_DXFER_NONE
            buf_len = 0
            buf_p = None
            prot = 3 << 1  # Non-data
        else:
            raise sgioFalied("Unknown ATA command : 0x%0.2X" % cmd)
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
                         device=1 << 6, # Enable LBA on ATA-5 and older drives
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
        sgio = self.prepareSgio(ATA_IDENTIFY, 0, 0, 0, buf)
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
        if self.sectors > 268435456:
            self.readCommand = ATA_READ_SECTORS_EXT
            self.verifyCommand = ATA_READ_VERIFY_SECTORS_EXT
            self.writeCommand = ATA_WRITE_SECTORS_EXT

        self.size = self.sectors / 2097152
        self.rpm = int.from_bytes(buf[434] + buf[435], byteorder='little')
        if self.rpm == 1:
            self.ssd = 1

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

    def readSectors(self, count, start):
        buf = ctypes.c_buffer(count * self.logicalSectorSize)
        sgio = self.prepareSgio(self.readCommand, 0, count, start, buf)
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
        sgio = self.prepareSgio(self.verifyCommand, 0, count, start, None)
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
        sgio = self.prepareSgio(self.writeCommand, 0, count, start, buf)
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
        sgio = self.prepareSgio(ATA_SMART_COMMAND, SMART_READ_VALUES, 1, SMART_LBA, buf)
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
        sgio = self.prepareSgio(ATA_SMART_COMMAND, SMART_READ_THRESHOLDS, 1, SMART_LBA, buf)
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
        buf = self.readSmartValues()
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

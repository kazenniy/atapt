#!/usr/bin/env python3

from atapt import atapt
import ctypes
import sys

if len(sys.argv) == 2:
    if sys.argv[1][0] != '/':
        dev = '/dev/' + sys.argv[1]
    else:
        dev = sys.argv[1]
    disk = atapt.atapt(dev)
else:
    print("use: example.py /dev/ice")
    exit(0)


# Disk identifycation
print()
print("Device:             " + disk.dev)
print("Model:              " + disk.model)
print("Firmware:           " + disk.firmware)
print("Serial:             " + disk.serial)
print("Sectors:            %d" % disk.sectors)
print("Size:               %d Gb" % disk.size)
if disk.formFactor != "":
    print("Form factor:        %s inch" % disk.formFactor)
if disk.ssd:
    print("Type:               SSD")
else:
    print("Type:               HDD")
    if disk.rpm > 1:
        print("RPM:                %d" % disk.rpm)
print("log. sector size:   %d bytes" % disk.logicalSectorSize)
print("phys. sector size:  %d bytes" % disk.physicalSectorSize)

disk.timeout = 1000
# Read SMART
print()
print("Read SMART")
disk.readSmart()
print()
print("SMART VALUES:")
print("ID# ATTRIBUTE NAME             TYPE     UPDATED   VALUE  WORST  THRESH  RAW")
for id in sorted(disk.smart):
    # [pre_fail, online, current, worst, raw, treshold]
    print("{:>3} {:<24} {:10} {:7}  {}  {}  {}    {}".format(id, disk.getSmartStr(id),
                                                             "Pre-fail" if disk.smart[id][0] else "Old_age",
                                                             "Always" if disk.smart[id][1] else "Offline",
                                                             "  %03d" % disk.smart[id][2],
                                                             "  %03d" % disk.smart[id][3],
                                                             "  %03d" % disk.smart[id][5], disk.getSmartRawStr(id)))
print("ata status: 0x%02X    ata error: 0x%02X" % (disk.ata_status, disk.ata_error))
print("duration: %f ms" % (disk.duration))

# Verify sector(s)
count = 1
print()
print("Verify last sector")
disk.verifySectors(count, disk.sectors - 1)
print("ata status: 0x%02X    ata error: 0x%02X" % (disk.ata_status, disk.ata_error))
print("duration: %f ms" % (disk.duration))


# Read sector(s)
count = 1
print()
print("Read last sector")
atapt.printBuf(disk.readSectors(count, disk.sectors - 1))
print("ata status: 0x%02X    ata error: 0x%02X" % (disk.ata_status, disk.ata_error))
print("duration: %f ms" % (disk.duration))


# Write sector(s)
count = 1
print()
print("\033[91mWARNING WRITE OPERATION IS POTENTIALLY DESTRUCTIVE!\033[0m")
print("If you continue it will rewrite last sector of your %s device" % disk.dev)
if input("Type YES to continue :") != "YES":
    exit()
print()
print("Write last sector")
buf = ctypes.c_buffer(disk.logicalSectorSize * count)
for i in range(disk.logicalSectorSize * count):
    buf[i] = int(i % 128)
atapt.printBuf(buf)
disk.writeSectors(count, disk.sectors - 1, buf)
print("ata status: 0x%02X    ata error: 0x%02X" % (disk.ata_status, disk.ata_error))
print("duration: %f ms" % (disk.duration))


# Read sector(s)
count = 1
print()
print("Read last sector")
atapt.printBuf(disk.readSectors(count, disk.sectors - 1))
print("ata status: 0x%02X    ata error: 0x%02X" % (disk.ata_status, disk.ata_error))
print("duration: %f ms" % (disk.duration))


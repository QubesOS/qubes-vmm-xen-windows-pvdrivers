#!/bin/sh

SRCIMG=winpvsources.img
ISOIMG=winpvdrivers.iso
MNT=mnt
ISODIR=iso/

sudo kpartx -a $SRCIMG
# Now, we're assuming that the part was mounted as /dev/mapper/loop0p1
# I'm not sure how to check this?
sudo mount /dev/mapper/loop0p1 $MNT

rm -f $ISODIR/*.msi
cp $MNT/winpvdrivers/gplpv_Vista2008*.msi $ISODIR/
if [ $? -ne 0 ]; then
    echo "No installation files found! Have you built the drivers?"
    sudo umount  $MNT 
    sudo kpartx -d $SRCIMG
    exit 1
fi
    
sudo umount  $MNT
sudo kpartx -d $SRCIMG
genisoimage -o $ISOIMG -m .gitignore -JR $ISODIR


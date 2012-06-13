#!/bin/sh

SRCIMG=winpvsources.img
MNT=mnt
OUTDIR=msi/

OUTPUT=`sudo kpartx -a -v $SRCIMG`
# sample output: add map loop0p1 (253:1): 0 2095104 linear /dev/loop0 2048
DEV=/dev/mapper/`echo $OUTPUT | cut -f 3 -d ' '`
sudo mount $DEV $MNT

mkdir -p $OUTDIR
rm -f $OUTDIR/*.msi
cp $MNT/winpvdrivers/gplpv_*.msi $OUTDIR/
if [ $? -ne 0 ]; then
    echo "No installation files found! Have you built the drivers?"
    sudo umount  $MNT 
    sudo kpartx -d $SRCIMG
    exit 1
fi

sudo umount  $MNT
sudo kpartx -d $SRCIMG

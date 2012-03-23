#!/bin/sh

IMG=winpvsources.img
IMG_MAXSZ=1g
MNT=mnt

truncate -s $IMG_MAXSZ $IMG
parted -s $IMG mklabel msdos
parted -s winpvsources.img mkpart primary ntfs 1 $IMG_MAXSZ

sudo kpartx -a winpvsources.img
# Now, we're assuming that the part was mounted as /dev/mapper/loop0p1
# I'm not sure how to check this?

mkfs.ntfs /dev/mapper/loop0p1 || exit 1
mkdir -p $MNT
sudo mount /dev/mapper/loop0p1 $MNT
sudo mkdir $MNT/winpvdrivers
#sudo cp -r win-pvdrivers.git/* $MNT/winpvdrivers/
sudo rsync --exclude $MNT --exclude $IMG -r * $MNT/winpvdrivers/
sudo umount /dev/mapper/loop0p1 
sudo kpartx -d winpvsources.img 


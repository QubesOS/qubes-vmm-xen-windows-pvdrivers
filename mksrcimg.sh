#!/bin/sh

IMG=winpvsources.img
IMG_MAXSZ=1g
MNT=mnt

truncate -s $IMG_MAXSZ $IMG
parted -s $IMG mklabel msdos
parted -s $IMG mkpart primary ntfs 1 $IMG_MAXSZ

sudo kpartx -a $IMG
# Now, we're assuming that the part was mounted as /dev/mapper/loop0p1
# I'm not sure how to check this?

mkfs.ntfs --fast /dev/mapper/loop0p1 || exit 1
mkdir -p $MNT
sudo mount /dev/mapper/loop0p1 $MNT
sudo mkdir $MNT/winpvdrivers
sudo rsync --exclude $MNT --exclude $IMG -r * $MNT/winpvdrivers/
sudo umount  $MNT
sudo kpartx -d $IMG


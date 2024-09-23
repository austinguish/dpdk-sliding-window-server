#!/usr/bin/bash
sudo sed -i '10d' /etc/fstab
sudo /usr/local/etc/emulab/mkextrafs.pl /mydata
sudo mount /dev/nvme0n1p4 /users/jiangyw/.cache
sudo chmod -R 770 /mydata

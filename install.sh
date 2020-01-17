#!/bin/bash
if [ "$EUID" -ne 0 ]; then
	echo "Please run as root"
	exit
fi
if [ ! -f "server.o" ]; then
	echo "You need to run build.sh first!"
	exit
fi
cp notiserver.pam /etc/pam.d/notiserver
cp server.o /usr/bin/notiserver
cp notiserver.service /usr/lib/systemd/system/
mkdir -p /etc/notiserver/

echo "Installed Notiserver! To use it start/enable notiserver.service!"
echo "Also note that you must put your certificate and key for SSL in /etc/notiserver/ as cert.pem and key.pem respectively"

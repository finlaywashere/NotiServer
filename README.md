# NotiServer

## Purpose

NotiServer is intended to be a lightweight server to manage sending notifications from your phone to computer or vice versa. It is different from other programs like KDEConnect because it has few dependencies

## Building

To build NotiServer simply run `build.sh`

## Installing

To install NotiServer simply run `install.sh` and then start/enable `notiserver.service` using SystemD

NOTE: SSL is required, so you must have an OpenSSL certificate and key in `/etc/notiserver/` as `cert.pem` and `key.pem` respectively.

## Client usage

Currently the client is just a very primitive Python script, eventually there will be a proper C client for desktop and a mobile app. To use the basic client simply run `python connect.sh` and follow the instructions.

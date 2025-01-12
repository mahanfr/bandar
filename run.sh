#!/bin/sh

set -xe

sudo setcap 'cap_setgid=+ep' ./build/bandar
sudo ./build/bandar -u 0 -m . -c /bin/sh

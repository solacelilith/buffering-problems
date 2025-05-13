#!/bin/sh

while true; do
    date -uR
    find /tmp/devices -maxdepth 1 -type f -cmin +20 -delete
    sleep 60
done
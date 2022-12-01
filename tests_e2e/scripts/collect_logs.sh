#!/usr/bin/env bash

set -euxo pipefail

logs_file_name="$HOME/logs.tgz"

echo "Collecting logs to $logs_file_name ..."

sudo tar --exclude='journal/*' --exclude='omsbundle' --exclude='omsagent' --exclude='mdsd' --exclude='scx*' \
         --exclude='*.so' --exclude='*__LinuxDiagnostic__*' --exclude='*.zip' --exclude='*.deb' --exclude='*.rpm' \
         -czf "$logs_file_name" \
         /var/log \
         /var/lib/waagent/ \
         /etc/waagent.conf

sudo chmod +r "$logs_file_name"


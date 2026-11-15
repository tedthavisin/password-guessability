#!/usr/bin/env bash
# Download the public wordlists the prototype uses into data/raw/.
set -euo pipefail
cd "$(dirname "$0")/../data/raw" 2>/dev/null || { mkdir -p "$(dirname "$0")/../data/raw"; cd "$(dirname "$0")/../data/raw"; }

curl -sSfL -o xato-top100k.txt \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt"
curl -sSfL -o english-20k.txt \
  "https://raw.githubusercontent.com/first20hours/google-10000-english/master/20k.txt"

wc -l xato-top100k.txt english-20k.txt

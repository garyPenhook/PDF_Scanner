#!/usr/bin/env sh
set -eu

python3 -m pip install --user -e ".[deep,yara,test]"
echo "Installed pdfscan. Run: pdfscan --help"

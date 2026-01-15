#!/bin/bash

# Bandit - Example Usage Script
# Copyright (C) 2026 Andy Dixon
# Contact: bandit@dixon.cx - https://www.dixon.cx
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# This script demonstrates the basic usage of the Bandit tool

set -e

echo "================================================"
echo "Bandit - Usage Examples"
echo "================================================"
echo ""

# Display system information
echo "1. Displaying system information:"
echo "-----------------------------------"
./target/release/bandit info
echo ""

echo "2. Example: Encrypting a file"
echo "-----------------------------------"
echo "Command: bandit encrypt -i <input-file> -o <output-file>"
echo "You will be prompted for a password."
echo ""

echo "3. Example: Decrypting a file"
echo "-----------------------------------"
echo "Command: bandit decrypt -i <encrypted-file> -o <output-file>"
echo "You will be prompted for the same password used during encryption."
echo ""

echo "4. Example: Using stdin/stdout"
echo "-----------------------------------"
echo "Encrypt: cat file.txt | bandit encrypt > encrypted.bin"
echo "Decrypt: bandit decrypt < encrypted.bin"
echo ""

echo "5. Example: Using with security key"
echo "-----------------------------------"
echo "Encrypt: bandit encrypt -i file.txt -o file.enc --security-key"
echo "Decrypt: bandit decrypt -i file.enc -o file.txt --security-key"
echo ""

echo "6. Example: Using AES-256-GCM"
echo "-----------------------------------"
echo "Encrypt: bandit encrypt -i file.txt -o file.enc --use-aes"
echo ""

echo "================================================"
echo "System is ready for use!"
echo "================================================"

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 19 15:44:40 2025

@author: ugo
"""

import ftplib

def test_utf8_mkd(server, port, user, password, dir_name_utf8):
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(server, port, timeout=5)
            ftp.login(user, password)
            
            print(f"C: MKD {dir_name_utf8}")
            response = ftp.mkd(dir_name_utf8)
            print(f"S: {response}")

            # Clean up after test
            ftp.rmd(dir_name_utf8)
            print(f"Removed directory: {dir_name_utf8}")

    except ftplib.error_perm as e:
        print(f"FTP permission error: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Example UTF-8 directory names to test:
    test_dirs = [
        "Café",
        "测试",
        "директория",
        "データ",
        "résumé"
    ]

    # Update with your FTP server info:
    FTP_SERVER = "127.0.0.1"
    FTP_PORT = 21
    FTP_USER = "username"
    FTP_PASS = "password"

    for d in test_dirs:
        print("\n--- Testing MKD with UTF-8 directory ---")
        test_utf8_mkd(FTP_SERVER, FTP_PORT, FTP_USER, FTP_PASS, d)

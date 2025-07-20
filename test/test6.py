#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 19 15:52:21 2025

@author: ugo
"""

import ftplib

def test_opts_utf8(server, port, user, password):
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(server, port, timeout=5)
            ftp.login(user, password)
            
            # Send OPTS UTF8 ON command
            print("C: OPTS UTF8 ON")
            response = ftp.sendcmd("OPTS UTF8 ON")
            print(f"S: {response}")
            
            # Check if server responded with 200
            if response.startswith('200'):
                print("OPTS UTF8 command is supported and accepted.")
            else:
                print("OPTS UTF8 command is not supported or rejected.")
    
    except ftplib.error_perm as e:
        print(f"FTP permission error: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    FTP_SERVER = "127.0.0.1"
    FTP_PORT = 21
    FTP_USER = "username"
    FTP_PASS = "password"

    test_opts_utf8(FTP_SERVER, FTP_PORT, FTP_USER, FTP_PASS)

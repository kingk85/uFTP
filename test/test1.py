#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 19 09:09:55 2025

@author: ugo
"""

import ftplib
import socket

def verify_ccc_no_prereq_check():
    """python
    Send CCC directly in an unencrypted session to verify if the server handles it incorrectly.
    """
    HOST = '127.0.0.1'
    PORT = 21
    USER = 'username'
    PASS = 'password'
    
    print("\n--- 2. Verifying Rule: CCC Without Preceding Security Exchange Check ---")
    
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(HOST, PORT, timeout=5)
            ftp.login(USER, PASS)
            print("Successfully logged in in a plaintext session.")
            
            print("C: CCC")
            # A non-compliant server will return 200 OK, indicating it accepted the command
            response = ftp.voidcmd('CCC')
            print(f"S: {response}")
            
            if response.startswith('200'):
                print("\n[!] VIOLATION CONFIRMED: Server accepted CCC command without an active TLS session.")
            else:
                print("\n[-] No violation detected or server returned an unexpected response.")

    except ftplib.error_perm as e:
        print(f"[-] Server correctly rejected the command. No violation. Server response: {e}")
    except Exception as e:
        print(f"\nError occurred: {e}")

if __name__ == "__main__":
    verify_ccc_no_prereq_check()
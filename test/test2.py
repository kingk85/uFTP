#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 19 09:20:47 2025

@author: ugo
"""

import ftplib
import socket

def verify_ccc_unprotected_reply():
    """
    Verify if the server returns an incorrect response code when CCC is sent over an unprotected connection.
    """
    HOST = '127.0.0.1'
    PORT = 21
    USER = 'username'
    PASS = 'password'
    
    print("\n--- 3. Verifying Rule: Response Code for Unprotected CCC ---")
    
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(HOST, PORT, timeout=5)
            ftp.login(USER, PASS)
            print("Successfully logged in in a plaintext session.")
            
            print("C: CCC")
            response = ftp.voidcmd('CCC')
            print(f"S: {response}")

    except ftplib.error_perm as e:
        response = str(e)
        print(f"S: {response}")
    except Exception as e:
        print(f"\nError occurred: {e}")
        return

    if '533' in response:
        print("\n[-] No violation detected. Server correctly responded with 533.")
    elif '200' in response or '502' in response:
        print(f"\n[!] VIOLATION CONFIRMED: Server responded with '{response.split()[0]}' instead of the required '533'.")
    else:
        print("\n[?] Server returned an unexpected response.")

if __name__ == "__main__":
    verify_ccc_unprotected_reply()

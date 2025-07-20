#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 19 18:15:07 2025

@author: ugo
"""

import socket
import ssl
import ftplib
from io import BytesIO

def log_command(direction, command, response=None):
    """Log FTP commands and responses"""
    if direction == "C":
        print(f"C: {command}")
    elif direction == "S":
        print(f"S: {response}")
    elif direction == "ERROR":
        print(f"ERROR: {command}")
    elif direction == "INFO":
        print(f"INFO: {command}")

def verify_rest_violations():
    """
    Verify REST-related sequence and implementation violations.
    """
    HOST = '127.0.0.1'
    PORT = 21
    USER = 'username'
    PASS = 'password'
    FILE = "test_rest.txt"
    CONTENT = b"1234567890"
    
    print("\n--- Verifying Rules: REST Command Sequence and Implementation ---")
    print("Test Objective: Verify that the REST command correctly limits subsequent commands and handles offsets")

    try:
        with ftplib.FTP() as ftp:
            # Enable debug mode to show all FTP interactions
            ftp.set_debuglevel(0)  # We handle display ourselves
            
            log_command("INFO", f"Connecting to {HOST}:{PORT}")
            ftp.connect(HOST, PORT, timeout=5)
            
            log_command("C", f"USER {USER}")
            ftp.login(USER, PASS)
            log_command("INFO", "Login successful")

            log_command("C", "TYPE I")
            resp = ftp.sendcmd("TYPE I")
            log_command("S", resp)

            # Upload test file
            log_command("C", f"STOR {FILE}")
            ftp.storbinary(f"STOR {FILE}", BytesIO(CONTENT))
            log_command("INFO", f"File uploaded successfully, content: {CONTENT} (length: {len(CONTENT)})")
            
            print("\n" + "="*60)
            # Scenario 1: Verify if RETR correctly handles the offset set by REST
            print("[+] Scenario 1: Verify if RETR correctly handles the offset set by REST")
            print("    RFC Requirement: RETR should start transferring from the byte position specified by REST")
            
            # Reset REST point
            rest_offset = 5
            log_command("C", f"REST {rest_offset}")
            try:
                response_rest2 = ftp.sendcmd(f"REST {rest_offset}")
                log_command("S", response_rest2)
                
                if not response_rest2.startswith('350'):
                    print(f"    REST {rest_offset} failed: {response_rest2}")
                    print(f"    Expected: 350 Restarting at {rest_offset}")
                    return
                else:
                    print(f"    REST set offset to byte {rest_offset}")
            except ftplib.error_perm as e:
                log_command("ERROR", f"REST {rest_offset} failed: {e}")
                return
            
            # Download file
            log_command("C", f"RETR {FILE}")
            out = BytesIO()
            ftp.retrbinary(f"RETR {FILE}", out.write)
            retrieved_content = out.getvalue()
            
            # Detailed analysis of results
            print(f"\n    Transfer Result Analysis:")
            print(f"    Original File Content: {CONTENT} (length: {len(CONTENT)})")
            print(f"    REST Offset: {rest_offset} (starting from byte {rest_offset})")
            print(f"    Expected Transferred Content: {CONTENT[rest_offset:]} (length: {len(CONTENT[rest_offset:])})")
            print(f"    Actual Transferred Content: {retrieved_content} (length: {len(retrieved_content)})")

            if len(retrieved_content) == len(CONTENT):
                print("\n    VIOLATION CONFIRMED: RETR implementation ignored the offset set by REST")
                print("    Actual Result: Downloaded the entire file, ignoring the REST offset")
                print(f"    Expected Result: Should only download {CONTENT[rest_offset:]} ({len(CONTENT[rest_offset:])} bytes)")
                print("    Violation Explanation: Violates RFC 959 regarding the REST command")
            elif len(retrieved_content) == len(CONTENT) - rest_offset:
                if retrieved_content == CONTENT[rest_offset:]:
                    print("    No violation detected. RETR correctly handled the REST offset.")
                else:
                    print("    VIOLATION CONFIRMED: Content mismatch, REST offset handled incorrectly")
                    print(f"    Actual Content: {retrieved_content}")
                    print(f"    Expected Content: {CONTENT[rest_offset:]}")
                    print("    Violation Explanation: Incorrect REST offset calculation")
            elif len(retrieved_content) > len(CONTENT):
                print("    VIOLATION CONFIRMED: Retrieved data length exceeds original file size")
                print(f"    Actual Length: {len(retrieved_content)} bytes")
                print(f"    Expected Maximum Length: {len(CONTENT)} bytes")
                print(f"    Expected Length after REST: {len(CONTENT[rest_offset:])} bytes")
                print("    Violation Explanation: Severe data transfer anomaly")
            else:
                print(f"    VIOLATION CONFIRMED: Unexpected retrieved content length")
                print(f"    Actual Length: {len(retrieved_content)} bytes")
                print(f"    Expected Length: {len(CONTENT[rest_offset:])} bytes")
                print("    Violation Explanation: Problem with REST command implementation")

            # Clean up test file
            try:
                log_command("C", f"DELE {FILE}")
                #ftp.delete(FILE)
                log_command("INFO", "Test file cleanup completed")
            except:
                log_command("ERROR", "Failed to cleanup test file")

    except Exception as e:
        print(f"\nError occurred: {e}")
        import traceback
        print("Detailed error information:")
        traceback.print_exc()
        print("\nPossible causes:")
        print("    - Server connection issues")
        print("    - Insufficient permissions")
        print("    - Server does not support certain commands")

if __name__ == "__main__":
    verify_rest_violations()
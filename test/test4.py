#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 19 15:07:22 2025

@author: ugo
"""

import socket

def verify_feat_space_indent():
    """
    Verify whether each feature in the FEAT response correctly starts with a single space.
    """
    HOST = '127.0.0.1'
    PORT = 21
    USER = 'username'
    PASS = 'password'
    
    print("\n--- 8. Verifying Rule: Missing Space Before FEAT Features ---")
    
    try:
        # Use raw socket connection for better reliability
        sock = socket.create_connection((HOST, PORT), timeout=10)
        
        # Read welcome message
        welcome = sock.recv(1024).decode().strip()
        print(f"S: {welcome}")
        
        # Login
        sock.sendall(b'USER username\r\n')
        resp = sock.recv(1024).decode().strip()
        print(f"C: USER username\nS: {resp}")
        
        sock.sendall(b'PASS password\r\n')
        resp = sock.recv(1024).decode().strip()
        print(f"C: PASS password\nS: {resp}")
        
        if not resp.startswith('230'):
            print("Login failed")
            return
            
        # Send FEAT command
        print("C: FEAT")
        sock.sendall(b'FEAT\r\n')
        
        # Read complete FEAT response
        full_response = b''
        while True:
            data = sock.recv(1024)
            if not data:
                break
            full_response += data
            # Check for end marker "211 End."
            if b'211 End.' in full_response:
                break
        
        # Parse response
        response_text = full_response.decode('utf-8', errors='ignore')
        lines = response_text.split('\r\n')
        
        print("S: Full response:")
        for line in lines:
            if line.strip():  # Print only non-empty lines
                print(f"  {line}")
        
        # Find feature lines (between 211- and 211 End.)
        feature_lines = []
        in_features = False
        
        for line in lines:
            if line.startswith('211-'):
                in_features = True
                continue
            elif line.startswith('211 '):
                break
            elif in_features and line.strip():
                feature_lines.append(line)
        
        print(f"\nParsed feature lines ({len(feature_lines)} lines):")
        for line in feature_lines:
            print(f"  '{line}'")
        
        # Check for violations
        violation_found = False
        if not feature_lines:
            print("No feature lines found.")
            return

        for line in feature_lines:
            # Per RFC 2389, each feature line must start with a single space
            if not line.startswith(' '):
                print(f"\n[!] VIOLATION CONFIRMED: Feature line '{line.strip()}' is missing the required leading space.")
                print(f"    Original line: '{line}' (length: {len(line)})")
                violation_found = True
            else:
                print(f"[-] Correct format: '{line.strip()}' (starts with space)")
        
        if not violation_found:
            print("\n[-] No violations detected. All feature lines are correctly formatted.")
        else:
            print(f"\n[!] RFC 2389 violation found: Feature lines must start with a space!")

    except Exception as e:
        print(f"\nError occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if 'sock' in locals():
            try:
                sock.close()
            except:
                pass

if __name__ == "__main__":
    verify_feat_space_indent()
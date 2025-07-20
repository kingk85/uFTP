#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 19 16:28:50 2025

@author: ugo
"""

import socket
import ssl

def verify_pbsz_prot_violations():
    """
    Combined verification of multiple sequence and validation violations related to PBSZ and PROT.
    """
    HOST = '127.0.0.1'
    PORT = 21
    USER = 'username'
    PASS = 'password'
    
    print("\n--- 12-15. Verifying Rules: PBSZ/PROT Command Sequences and Validation ---")

    # Scenario 1: Invoke PBSZ without prior security exchange
    print("\n[+] Scenario 1: Invoke PBSZ on plaintext connection")
    try:
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
            sock.recv(1024)
            sock.sendall(b'PBSZ 0\r\n')
            print("C: PBSZ 0")
            response = sock.recv(1024).decode().strip()
            print(f"S: {response}")
            if response.startswith('200'):
                print("  -> VIOLATION CONFIRMED: Server accepted PBSZ without prior security exchange.")
            else:
                print("  -> No violation detected for this case.")
    except Exception as e:
        print(f"  -> Error occurred: {e}")

    # Scenario 2: Invoke PBSZ with invalid parameters
    print("\n[+] Scenario 2: Invoke PBSZ with invalid parameters")
    try:
        # Need a TLS connection to proceed
        sock = socket.create_connection((HOST, PORT), timeout=5)
        sock.recv(1024)
        sock.sendall(b'AUTH TLS\r\n')
        sock.recv(1024)
        
        # Create SSL context that doesn't verify certificates
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ssock = context.wrap_socket(sock, server_hostname=HOST)
        
        ssock.sendall(b'PBSZ not_a_number\r\n')
        print("C: PBSZ not_a_number")
        response = ssock.recv(1024).decode().strip()
        print(f"S: {response}")
        if response.startswith('200'):
            print("  -> VIOLATION CONFIRMED: Server responded with 200 OK to invalid PBSZ parameter instead of 501.")
        else:
            print("  -> No violation detected for this case.")
        
        # Scenario 3: Invoke PROT without calling PBSZ first
        print("\n[+] Scenario 3: Invoke PROT on TLS connection without prior PBSZ")
        ssock.sendall(b'PROT P\r\n')
        print("C: PROT P")
        response_prot = ssock.recv(1024).decode().strip()
        print(f"S: {response_prot}")
        if response_prot.startswith('200'):
            print("  -> VIOLATION CONFIRMED: Server accepted PROT without prior PBSZ.")
        else:
            print("  -> No violation detected for this case.")

    except Exception as e:
        print(f"\nError occurred: {e}")
    finally:
        if 'ssock' in locals():
            ssock.close()

if __name__ == "__main__":
    verify_pbsz_prot_violations()
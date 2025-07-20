#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jul 19 14:54:55 2025

@author: ugo
"""

import socket
import ssl

def verify_auth_reauth_violation():
    """
    Verify whether the server enforces re-authentication after re-issuing the AUTH command.
    """
    HOST = '127.0.0.1'
    PORT = 21
    USER = 'username'
    PASS = 'password'

    print("--- Verifying Rule: Re-authentication Required After Re-issuing AUTH Command ---")

    try:
        # Step 1: Connect and log in in plaintext
        print("\n[+] Step 1: Establish plaintext connection and log in...")
        sock = socket.create_connection((HOST, PORT), timeout=5)
        print(f"S: {sock.recv(1024).decode().strip()}")

        sock.sendall(f'USER {USER}\r\n'.encode())
        print(f"C: USER {USER}")
        print(f"S: {sock.recv(1024).decode().strip()}")

        sock.sendall(f'PASS {PASS}\r\n'.encode())
        print(f"C: PASS {PASS}")
        response_login = sock.recv(1024).decode().strip()
        print(f"S: {response_login}")

        if not response_login.startswith('230'):
            print("[-] Login failed; test cannot continue.")
            return

        # Step 2: Verify logged-in status
        print("\n[+] Step 2: Execute PWD command in plaintext mode to verify login status...")
        sock.sendall(b'PWD\r\n')
        print("C: PWD")
        response_pwd1 = sock.recv(1024).decode().strip()
        print(f"S: {response_pwd1}")
        if not response_pwd1.startswith('257'):
            print("[-] PWD command failed; cannot confirm login status.")
            return
        print("    -> Status confirmed: User is logged in.")

        # Step 3: Re-issue AUTH command to reset security state
        print("\n[+] Step 3: Re-issue AUTH TLS command to upgrade connection to encrypted mode...")
        sock.sendall(b'AUTH TLS\r\n')
        print("C: AUTH TLS")
        response_auth = sock.recv(1024).decode().strip()
        print(f"S: {response_auth}")
        
        if not response_auth.startswith('234'):
            print(f"[-] AUTH TLS command failed: {response_auth}")
            return
        
        # Create SSL context that does not verify certificates
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Wrap regular socket into SSL socket
        ssock = context.wrap_socket(sock, server_hostname=HOST)
        print("    -> TLS handshake successful; connection is encrypted.")

        # Step 4: Attempt authenticated command again without re-authenticating
        print("\n[+] Step 4: In encrypted mode, execute PWD command directly without re-logging in...")
        ssock.sendall(b'PWD\r\n')
        print("C: PWD")
        response_pwd2 = ssock.recv(1024).decode().strip()
        print(f"S: {response_pwd2}")

        # Final analysis
        print("\n--- Final Analysis ---")
        if response_pwd2.startswith('257'):
            print("[!] VIOLATION CONFIRMED: Server accepted the command, proving user login state was retained!")
            print("[!] This is a high-risk authentication bypass vulnerability.")
        elif response_pwd2.startswith('530'):
            print("[-] NO VIOLATION: Server correctly rejected the command, requiring re-authentication.")
        else:
            print(f"[?] UNEXPECTED RESPONSE: Server returned an unexpected response code: {response_pwd2}")

    except Exception as e:
        print(f"\nError occurred: {e}")
    finally:
        if 'ssock' in locals():
            ssock.close()
        elif 'sock' in locals():
            sock.close()

if __name__ == "__main__":
    verify_auth_reauth_violation()

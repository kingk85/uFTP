import unittest
from ftplib import FTP, error_perm, error_temp
import os
from io import BytesIO
import time
import ssl
import socket
import ftplib
import re

FTP_HOST = '127.0.0.1'
FTP_PORT = 21
FTP_USER = 'username'
FTP_PASS = 'password'

TEST_FILENAME = 'test.txt'
TEST_CONTENT = b'1234567890'  # 10 bytes known content
DOWNLOAD_FILENAME = 'downloaded_test.txt'
UPLOAD_FILENAME = 'upload_test.txt'
RESUME_FILENAME = 'resume_test.txt'


class FTPServerRFCComplianceTests(unittest.TestCase):
    
    def setUp(self):
        # Create local test file first
        with open(TEST_FILENAME, 'wb') as f:
            f.write(TEST_CONTENT)
    
        # Connect and login
        self.ftp = FTP()
        self.ftp.connect(FTP_HOST, FTP_PORT, timeout=10)
        self.ftp.login(FTP_USER, FTP_PASS)
    
        # Upload file to FTP server
        with open(TEST_FILENAME, 'rb') as f:
            self.ftp.storbinary(f"STOR {TEST_FILENAME}", f)


    def tearDown(self):
        try:
            # Remove test files from server if they exist
            for fname in [TEST_FILENAME, UPLOAD_FILENAME, RESUME_FILENAME]:
                try:
                    self.ftp.delete(fname)
                except Exception:
                    pass
            self.ftp.quit()
        except Exception:
            self.ftp.close()

        # Remove local temp files
        for fname in [TEST_FILENAME, DOWNLOAD_FILENAME, UPLOAD_FILENAME]:
            if os.path.exists(fname):
                os.remove(fname)

    def test_stor_write(self):
        original_data = b'abcdefghij'
        with open(RESUME_FILENAME, 'wb') as f:
            f.write(original_data)
        with open(RESUME_FILENAME, 'rb') as f:
            self.ftp.storbinary(f'STOR {RESUME_FILENAME}', f)

        downloaded = BytesIO()
        self.ftp.retrbinary(f'RETR {RESUME_FILENAME}', downloaded.write)
        self.assertEqual(downloaded.getvalue(), original_data)

    def test_stor_resume_with_rest(self):
        original_data = b'abcdefghij'
        resume_data = b'XYZ'
        expected_data = b'abcdeXYZij'

        with open(RESUME_FILENAME, 'wb') as f:
            f.write(original_data)
        with open(RESUME_FILENAME, 'rb') as f:
            self.ftp.storbinary(f'STOR {RESUME_FILENAME}', f)

        self.ftp.sendcmd('REST 5')
        self.ftp.storbinary(f'STOR {RESUME_FILENAME}', BytesIO(resume_data))

        downloaded = BytesIO()
        self.ftp.retrbinary(f'RETR {RESUME_FILENAME}', downloaded.write)
        self.assertEqual(downloaded.getvalue(), expected_data)

    def test_appe_append(self):
        initial_data = b'12345'
        append_data = b'67890'
        expected_data = b'1234567890'

        with open(RESUME_FILENAME, 'wb') as f:
            f.write(initial_data)
        with open(RESUME_FILENAME, 'rb') as f:
            self.ftp.storbinary(f'STOR {RESUME_FILENAME}', f)

        self.ftp.storbinary(f'APPE {RESUME_FILENAME}', BytesIO(append_data))

        downloaded = BytesIO()
        self.ftp.retrbinary(f'RETR {RESUME_FILENAME}', downloaded.write)
        self.assertEqual(downloaded.getvalue(), expected_data)


    def test_220_service_ready(self):
        welcome = self.ftp.getwelcome()
        self.assertTrue(welcome.startswith('220'), f"Expected 220 response, got: {welcome}")

    def test_user_login_success(self):
        resp = self.ftp.login(user=FTP_USER, passwd=FTP_PASS)
        self.assertTrue(resp.startswith('230'), f"Login failed or unexpected response: {resp}")

    def test_user_login_fail(self):
        with self.assertRaises((error_perm, error_temp)):
            self.ftp.login(user='wronguser', passwd='wrongpass')

    def test_pwd_and_cwd(self):
        pwd = self.ftp.pwd()
        self.assertTrue(pwd.startswith('/'), f"PWD should return directory path, got: {pwd}")
        resp = self.ftp.cwd('/')
        self.assertTrue(resp.startswith('250'), f"CWD should succeed with 250 response, got: {resp}")
            

    def Disabledtest_mkdr(self):
        test_dirs = [
            "dir1",
            "dir2",
            "dir3"
        ]
        
        self.utf8_mkd(test_dirs)
        


    def test_utf8_mkd(self):
        test_dirs = ["директория", "データ", "résumé"]

        with ftplib.FTP() as ftp:
            ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
            ftp.login(FTP_USER, FTP_PASS)
            ftp.encoding = 'utf-8'

            # Enable UTF-8 option
            try:
                ftp.sendcmd("OPTS UTF8 ON")
            except Exception:
                pass

            for d in test_dirs:
                # Try to remove if exists
                try:
                    ftp.rmd(d)
                except ftplib.error_perm:
                    pass

                response = ftp.mkd(d)

                # Match response code and directory name more flexibly
                m = re.match(r'257\s+"?(.+?)"?\s', response)
                assert m is not None, f"MKD response format incorrect: {response}"
                dir_in_response = m.group(1)
                assert dir_in_response == d, f"Directory name mismatch: expected {d}, got {dir_in_response}"

                # Cleanup
                ftp.rmd(d)


    def utf8_mkd(self, test_dirs):
        #test_dirs = [
        #    "Café",
        #    "测试",
        #    "директория",
        #    "データ",
        #    "résumé"
        #]

        with ftplib.FTP() as ftp:
            ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
            ftp.login(FTP_USER, FTP_PASS)

            ftp.encoding = 'utf-8'
            try:
                print("C: OPTS UTF8 ON")
                response = ftp.sendcmd("OPTS UTF8 ON")
                print(f"S: {repr(response)}")
            except Exception as e:
                print(f"Warning: OPTS UTF8 ON failed: {e}")

            for dir_name_utf8 in test_dirs:
                with self.subTest(dir=dir_name_utf8):
                    try:
                        # Delete if exists
                        try:
                            ftp.cwd(dir_name_utf8)
                            ftp.cwd("..")
                            ftp.rmd(dir_name_utf8)
                            print(f"Deleted existing dir: {dir_name_utf8}")
                        except ftplib.error_perm:
                            pass

                        # Create directory
                        print(f"C: MKD {dir_name_utf8}")
                        response = ftp.mkd(dir_name_utf8)
                        print(f"S: {repr(response)}")

                        self.assertTrue(response.startswith('257'),
                            f"MKD failed: Server responded with: {repr(response)}")

                        # Verify directory is accessible by changing to it
                        ftp.cwd(dir_name_utf8)
                        ftp.cwd("..")

                        # Cleanup
                        ftp.rmd(dir_name_utf8)
                        print(f"Removed directory: {dir_name_utf8}")

                    except Exception as e:
                        self.fail(f"Exception for directory '{dir_name_utf8}': {e}")


    def test_pbsz_prot_violations(self):
        HOST = '127.0.0.1'
        PORT = 21

        print("\n--- 12-15. Verifying Rules: PBSZ/PROT Command Sequences and Validation ---")

        # Scenario 1: Invoke PBSZ without prior security exchange (plaintext)
        print("\n[+] Scenario 1: Invoke PBSZ on plaintext connection")
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
            banner = sock.recv(1024).decode()
            print(f"S: {banner.strip()}")
            sock.sendall(b'PBSZ 0\r\n')
            print("C: PBSZ 0")
            response = sock.recv(1024).decode().strip()
            print(f"S: {response}")
            self.assertNotEqual(response.startswith('200'), True, "Violation: PBSZ accepted without security.")

        # Scenario 2 & 3: Use TLS connection for further checks
        print("\n[+] Scenario 2: Invoke PBSZ with invalid parameters")
        sock = socket.create_connection((HOST, PORT), timeout=5)
        banner = sock.recv(1024).decode()
        print(f"S: {banner.strip()}")

        sock.sendall(b'AUTH TLS\r\n')
        auth_response = sock.recv(1024).decode().strip()
        print(f"C: AUTH TLS\nS: {auth_response}")

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ssock = context.wrap_socket(sock, server_hostname=HOST)

        try:
            ssock.sendall(b'PBSZ not_a_number\r\n')
            print("C: PBSZ not_a_number")
            response = ssock.recv(1024).decode().strip()
            print(f"S: {response}")
            self.assertNotEqual(response.startswith('200'), True,
                                "Violation: Server accepted invalid PBSZ parameter.")

            print("\n[+] Scenario 3: Invoke PROT on TLS connection without prior PBSZ")
            ssock.sendall(b'PROT P\r\n')
            print("C: PROT P")
            response_prot = ssock.recv(1024).decode().strip()
            print(f"S: {response_prot}")
            self.assertNotEqual(response_prot.startswith('200'), True,
                                "Violation: Server accepted PROT without prior PBSZ.")
        finally:
            ssock.close()

    
    def test_feat_space_indent(self):
        """
        Verify whether each feature in the FEAT response correctly starts with a single space.
        """
        HOST = '127.0.0.1'
        PORT = 21
        USER = 'username'
        PASS = 'password'
        
        print("\n--- 8. Verifying Rule: Missing Space Before FEAT Features ---")
        
        try:
            sock = socket.create_connection((HOST, PORT), timeout=10)
            
            welcome = sock.recv(1024).decode().strip()
            print(f"S: {welcome}")
            
            sock.sendall(f'USER {USER}\r\n'.encode())
            resp = sock.recv(1024).decode().strip()
            print(f"C: USER {USER}\nS: {resp}")
            
            sock.sendall(f'PASS {PASS}\r\n'.encode())
            resp = sock.recv(1024).decode().strip()
            print(f"C: PASS {PASS}\nS: {resp}")
            
            self.assertTrue(resp.startswith('230'), "Login failed")
            
            sock.sendall(b'FEAT\r\n')
            
            full_response = b''
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                full_response += data
                if b'211 End.' in full_response:
                    break
            
            response_text = full_response.decode('utf-8', errors='ignore')
            lines = response_text.split('\r\n')
            
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
            
            self.assertTrue(len(feature_lines) > 0, "No feature lines found in FEAT response")
            
            for line in feature_lines:
                self.assertTrue(line.startswith(' '), f"Feature line does not start with a space: '{line}'")
        
        except Exception as e:
            self.fail(f"Exception occurred during FEAT space indent verification: {e}")
        
        finally:
            if 'sock' in locals():
                try:
                    sock.close()
                except:
                    pass


    def test_pasv_retr(self):
        self.ftp.login(FTP_USER, FTP_PASS)
        self.ftp.set_pasv(True)
        with open(DOWNLOAD_FILENAME, 'wb') as f:
            self.ftp.retrbinary(f'RETR {TEST_FILENAME}', f.write)

        self.assertTrue(os.path.exists(DOWNLOAD_FILENAME), "Downloaded file does not exist")

        # Check downloaded file size is > 0
        self.assertGreater(os.path.getsize(DOWNLOAD_FILENAME), 0, "Downloaded file is empty")



    def test_active_retr(self):
        self.ftp.set_pasv(False)
        try:
            with open(DOWNLOAD_FILENAME, 'wb') as f:
                self.ftp.retrbinary(f'RETR {TEST_FILENAME}', f.write)
        except EOFError:
            self.skipTest("Active mode data connection failed")
        self.assertTrue(os.path.exists(DOWNLOAD_FILENAME), "Downloaded file does not exist")

    def test_rest_command(self):
        with open(TEST_FILENAME, 'rb') as f:
            f.seek(5)
            expected_data = f.read()

        self.ftp.sendcmd('REST 5')
        data = bytearray()
        self.ftp.retrbinary(f'RETR {TEST_FILENAME}', data.extend)
        self.assertEqual(data, expected_data, f"REST transfer mismatch.\nExpected: {expected_data!r}\nActual  : {data!r}")

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

    def test_rest_stor_resume_explicit(self):
        """
        Test resuming an upload using REST + STOR.
        This should append or overwrite starting from the specified offset.
        """
        original_data = b'abcdefghij'  # 10 bytes
        resume_data = b'XYZ'           # Will overwrite at offset 5 → expect: abcdeXYZij
        expected_data = b'abcdeXYZij'

        # Step 1: Upload original data
        with open(RESUME_FILENAME, 'wb') as f:
            f.write(original_data)
        with open(RESUME_FILENAME, 'rb') as f:
            self.ftp.storbinary(f'STOR {RESUME_FILENAME}', f)

        # Step 2: Resume upload from offset 5 with 'XYZ'
        self.ftp.sendcmd('REST 5')
        self.ftp.storbinary(f'STOR {RESUME_FILENAME}', BytesIO(resume_data))

        # Step 3: Download and verify final file content
        downloaded = BytesIO()
        self.ftp.retrbinary(f'RETR {RESUME_FILENAME}', downloaded.write)
        result = downloaded.getvalue()

        self.assertEqual(result, expected_data,
                         f"REST+STOR resume failed.\nExpected: {expected_data}\nActual  : {result}")


    def test_rest_violations(self):
        FILE = "test_rest.txt"
        CONTENT = b"1234567890"

        print("\n--- Verifying Rules: REST Command Sequence and Implementation ---")
        print("Test Objective: Verify that the REST command correctly limits subsequent commands and handles offsets")


        try:
            with ftplib.FTP() as ftp:
                ftp.set_debuglevel(0)

                ftp.connect(FTP_HOST, FTP_PORT, timeout=5)

                ftp.login(FTP_USER, FTP_PASS)
                self.log_command("INFO", "Login successful")

                self.log_command("C", "TYPE I")
                resp = ftp.sendcmd("TYPE I")
                self.log_command("S", resp)

                self.log_command("C", f"STOR {FILE}")
                ftp.storbinary(f"STOR {FILE}", BytesIO(CONTENT))
                self.log_command("INFO", f"File uploaded successfully, content: {CONTENT} (length: {len(CONTENT)})")

                print("\n" + "="*60)
                print("[+] Scenario 1: Verify if RETR correctly handles the offset set by REST")
                print("    RFC Requirement: RETR should start transferring from the byte position specified by REST")

                rest_offset = 5
                self.log_command("C", f"REST {rest_offset}")
                response_rest2 = ftp.sendcmd(f"REST {rest_offset}")
                self.log_command("S", response_rest2)
                self.assertTrue(response_rest2.startswith('350'), f"REST {rest_offset} failed: {response_rest2}")

                self.log_command("C", f"RETR {FILE}")
                out = BytesIO()
                ftp.retrbinary(f"RETR {FILE}", out.write)
                retrieved_content = out.getvalue()

                print(f"\n    Transfer Result Analysis:")
                print(f"    Original File Content: {CONTENT} (length: {len(CONTENT)})")
                print(f"    REST Offset: {rest_offset} (starting from byte {rest_offset})")
                print(f"    Expected Transferred Content: {CONTENT[rest_offset:]} (length: {len(CONTENT[rest_offset:])})")
                print(f"    Actual Transferred Content: {retrieved_content} (length: {len(retrieved_content)})")

                # Assertion based on REST behavior
                if len(retrieved_content) == len(CONTENT):
                    self.fail("RETR ignored REST offset: entire file downloaded.")
                elif len(retrieved_content) == len(CONTENT) - rest_offset and retrieved_content == CONTENT[rest_offset:]:
                    print("No violation detected. RETR correctly handled the REST offset.")
                else:
                    self.fail("REST offset handled incorrectly or data mismatch.")

                try:
                    self.log_command("C", f"DELE {FILE}")
                    # ftp.delete(FILE)  # Uncomment if delete supported by server
                    self.log_command("INFO", "Test file cleanup completed")
                except Exception:
                    self.log_command("ERROR", "Failed to cleanup test file")

        except Exception as e:
            self.fail(f"Error during REST violation test: {e}")


    def test_rest_stor_resume(self):
        with open(UPLOAD_FILENAME, 'wb') as f:
            f.write(TEST_CONTENT)
        with open(UPLOAD_FILENAME, 'rb') as f:
            self.ftp.storbinary(f'STOR {RESUME_FILENAME}', f)

        self.ftp.sendcmd('REST 5')
        with open(UPLOAD_FILENAME, 'rb') as f:
            f.seek(5)
            resp = self.ftp.storbinary(f'STOR {RESUME_FILENAME}', f)
        self.assertTrue(resp.startswith('226') or resp.startswith('250'),
                        f"STOR after REST failed: {resp}")

    def test_rest_cleared_after_retr(self):
        self.ftp.sendcmd('REST 5')
        self.ftp.retrbinary(f'RETR {TEST_FILENAME}', lambda _: None)  # discard output

        # Next RETR should start from 0
        data = bytearray()
        self.ftp.retrbinary(f'RETR {TEST_FILENAME}', data.extend)
        with open(TEST_FILENAME, 'rb') as f:
            expected = f.read()
        self.assertEqual(data, expected, "REST offset wasn't cleared after first RETR")

    def test_stor_upload(self):
        with open(UPLOAD_FILENAME, 'wb') as f:
            f.write(b'This is test upload content.')
        with open(UPLOAD_FILENAME, 'rb') as f:
            resp = self.ftp.storbinary(f'STOR {UPLOAD_FILENAME}', f)
        self.assertTrue(resp.startswith('226') or resp.startswith('250'),
                        f"STOR command should succeed, got: {resp}")



    def test_ccc_without_prereq(self):
        """Verify that the server rejects CCC command sent without an active TLS session."""
        try:
            with FTP() as ftp:
                ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
                ftp.login(FTP_USER, FTP_PASS)

                # Send CCC command in plaintext session
                response = ftp.voidcmd('CCC')

                # If the server responds with 200, that is a violation
                self.assertFalse(response.startswith('200'),
                                 f"Server incorrectly accepted CCC command without TLS: {response}")

        except error_perm as e:
            # Expected behavior: server rejects CCC in plaintext with 5xx error
            self.assertTrue(str(e).startswith('5'), f"Unexpected permission error response: {e}")

        except Exception as e:
            self.fail(f"Unexpected exception during CCC command test: {e}")

    def test_ccc_unprotected_reply(self):
        """
        Verify if the server returns the correct 533 response code
        when CCC is sent over an unprotected connection.
        """
        try:
            with FTP() as ftp:
                ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
                ftp.login(FTP_USER, FTP_PASS)

                response = ftp.voidcmd('CCC')

        except error_perm as e:
            response = str(e)

        except Exception as e:
            self.fail(f"Unexpected exception during CCC command test: {e}")

        # The RFC requires the server to respond with 533 if CCC is disallowed in the current context
        if '533' in response:
            pass  # Correct behavior
        elif response.startswith('200') or response.startswith('502'):
            self.fail(f"Violation: Server responded with '{response.split()[0]}' instead of '533'.")
        else:
            self.fail(f"Unexpected server response: {response}")

    def test_rest_offset_compliance(self):
        """
        Verify that RETR respects REST offset and doesn't transfer the whole file.
        """
        self.ftp.login(FTP_USER, FTP_PASS)
        self.ftp.sendcmd("TYPE I")

        FILE = "test_rest.txt"
        CONTENT = b"1234567890"
        rest_offset = 5

        # Upload known content
        self.ftp.storbinary(f"STOR {FILE}", BytesIO(CONTENT))

        # Set REST offset
        resp = self.ftp.sendcmd(f"REST {rest_offset}")
        self.assertTrue(resp.startswith('350'), f"Expected 350 response to REST, got: {resp}")

        # RETR after REST
        out = BytesIO()
        self.ftp.retrbinary(f"RETR {FILE}", out.write)
        retrieved_content = out.getvalue()

        expected = CONTENT[rest_offset:]

        # Validate
        self.assertEqual(retrieved_content, expected,
                         f"REST offset not respected.\nExpected: {expected!r}\nActual  : {retrieved_content!r}")

        # Clean up (optional, since tearDown removes test files)
        try:
            self.ftp.delete(FILE)
        except:
            pass


    def test_auth_reauth_violation(self):
        """
        Verify whether the server enforces re-authentication after re-issuing the AUTH command.
        """
        HOST = FTP_HOST
        PORT = FTP_PORT
        USER = FTP_USER
        PASS = FTP_PASS

        print("\n--- Verifying Rule: Re-authentication Required After Re-issuing AUTH Command ---")

        sock = None
        ssock = None

        try:
            # Step 1: Connect and log in in plaintext
            sock = socket.create_connection((HOST, PORT), timeout=5)
            welcome = sock.recv(1024).decode().strip()
            print(f"S: {welcome}")

            sock.sendall(f'USER {USER}\r\n'.encode())
            print(f"C: USER {USER}")
            response_user = sock.recv(1024).decode().strip()
            print(f"S: {response_user}")

            sock.sendall(f'PASS {PASS}\r\n'.encode())
            print(f"C: PASS {'*' * len(PASS)}")
            response_login = sock.recv(1024).decode().strip()
            print(f"S: {response_login}")

            self.assertTrue(response_login.startswith('230'), "Login failed; test cannot continue.")

            # Step 2: Verify logged-in status
            sock.sendall(b'PWD\r\n')
            print("C: PWD")
            response_pwd1 = sock.recv(1024).decode().strip()
            print(f"S: {response_pwd1}")
            self.assertTrue(response_pwd1.startswith('257'), "PWD command failed; cannot confirm login status.")

            # Step 3: Re-issue AUTH TLS command to reset security state
            sock.sendall(b'AUTH TLS\r\n')
            print("C: AUTH TLS")
            response_auth = sock.recv(1024).decode().strip()
            print(f"S: {response_auth}")

            self.assertTrue(response_auth.startswith('234'), f"AUTH TLS command failed: {response_auth}")

            # Wrap socket in SSL context (skip certificate verification)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            ssock = context.wrap_socket(sock, server_hostname=HOST)
            print("    -> TLS handshake successful; connection is encrypted.")

            # Step 4: Attempt authenticated command again without re-authenticating
            ssock.sendall(b'PWD\r\n')
            print("C: PWD")
            response_pwd2 = ssock.recv(1024).decode().strip()
            print(f"S: {response_pwd2}")

            # Analyze result
            if response_pwd2.startswith('257'):
                self.fail("VIOLATION: Server accepted PWD command after AUTH TLS without re-authentication!")
            elif response_pwd2.startswith('530'):
                # Correct behavior: require login after re-auth
                pass
            else:
                self.fail(f"Unexpected server response after AUTH TLS: {response_pwd2}")

        except Exception as e:
            self.fail(f"Exception occurred during AUTH re-auth test: {e}")

        finally:
            if ssock:
                ssock.close()
            elif sock:
                sock.close()


    def test_quit(self):
        resp = self.ftp.quit()
        self.assertTrue(resp.startswith('221'), f"QUIT should respond with 221, got: {resp}")

    def test_invalid_command(self):
        try:
            resp = self.ftp.sendcmd('FOOBAR')
            self.assertTrue(resp.startswith('500') or resp.startswith('502'),
                            f"Invalid command should respond with 5xx error, got: {resp}")
        except error_perm as e:
            self.assertTrue(str(e).startswith('500') or str(e).startswith('502'),
                            f"Invalid command error should start with 5xx, got: {e}")


if __name__ == '__main__':
    unittest.main()

import pefile
import binascii
import arc4
import time

banner = '''

  _____             _ _____ _____     _____             __ _         ______      _                  _             
 |_   _|           | |_   _|  __ \   / ____|           / _(_)       |  ____|    | |                | |            
   | |  ___ ___  __| | | | | |  | | | |     ___  _ __ | |_ _  __ _  | |__  __  _| |_ _ __ __ _  ___| |_ ___  _ __ 
   | | / __/ _ \/ _` | | | | |  | | | |    / _ \| '_ \|  _| |/ _` | |  __| \ \/ / __| '__/ _` |/ __| __/ _ \| '__|
  _| || (_|  __/ (_| |_| |_| |__| | | |___| (_) | | | | | | | (_| | | |____ >  <| |_| | | (_| | (__| || (_) | |   
 |_____\___\___|\__,_|_____|_____/   \_____\___/|_| |_|_| |_|\__, | |______/_/\_\\__|_|  \__,_|\___|\__\___/|_|   
                                                              __/ |                                               
                                                             |___/                                                
                                                    
                                                    by: 0x0d4y

'''

print(banner)
time.sleep(2)

def decrypt_rc4(key, encrypt_data):
    arc4_cipher = arc4.ARC4(key)
    return arc4_cipher.decrypt(encrypt_data)

def extract_pe_section(file_path, section_name, key_size, enc_data):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        # Search for the desired section
        for section in pe.sections:
            if section.Name.decode().rstrip('\x00') == section_name:
                # Extract raw data
                raw_data = section.get_data()

                # Extract the key and the enrypted data
                key_data = raw_data[:key_size]
                remaining_data = raw_data[key_size:key_size + enc_data]

                # Convert to hexadecimal and print
                key_hex = binascii.hexlify(key_data).decode('utf-8')
                remaining_hex = binascii.hexlify(remaining_data).decode('utf-8')

                print(f"\n[!] Hex Key ({key_size} bytes): {key_hex}")
                print(f"\n[!] Hex Encrypted Data ({enc_data} bytes): {remaining_hex}")

                # Decrypt using RC4
                key = binascii.unhexlify(key_hex)
                encrypted_data = binascii.unhexlify(remaining_hex)
                decrypted_data = decrypt_rc4(key, encrypted_data)

                print("\n[+] Decrypted Data:")
                print('\n'.join(part.decode('latin-1') for part in decrypted_data.split(b'\x00') if part))
                break
        else:
            print(f"\n[-] Section '{section_name}' not found in the PE file. [-]")

    except Exception as e:
        print(f"\n[-] Error processing the PE file: {e} [-]")

# Prompt the user for the PE file path, section name, key size, and encrypt data size
pe_file_path = input("\n[+] Enter the IcedID file path: ")
section_name = input("[+] Enter the name of the PE section to extract the encrypted config: ")
key_size = int(input("[+] Enter the number of the first bytes for the RC4 key: "))
enc_data = int(input("[+] Enter the number of bytes after the key where is the encrypted data: "))
time.sleep(2)

# Call the function to extract and print section data
extract_pe_section(pe_file_path, section_name, key_size, enc_data)

import pefile
import binascii
import arc4

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

                # Extract the key and the encrypted data
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

# Static information
section_name = ".data"
key_size = 8
enc_data = 248

# Loop infinito
while True:
    try:
        # Prompt the user for the PE file path
        pe_file_path = input("\n[+] Enter the IcedID file path (Ctrl+C to exit): ")

        # Call the function to extract and print section data
        extract_pe_section(pe_file_path, section_name, key_size, enc_data)
        
    except KeyboardInterrupt:
        print("\n[!] Program terminated by user (Ctrl+C). Goodbye!")
        break
    except Exception as e:
        print(f"\n[-] An error occurred: {e} [-]")

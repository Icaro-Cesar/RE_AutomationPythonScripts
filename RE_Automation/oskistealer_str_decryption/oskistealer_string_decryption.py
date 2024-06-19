'''

    Author:         0x0d4y
    Description:    Base64 decode and RC4 decryption strings, and setting comments after the decryption

'''



import base64
import binascii
import arc4

rc4_key = b'<hex_key>' # <= RC4 key

def decrypt_rc4(key, encrypt_data):
    arc4_cipher = arc4.ARC4(key)
    return arc4_cipher.decrypt(encrypt_data)

dec_function = "" # <= Decryption Function Address without ""
cross_references =  bv.get_code_refs(dec_function)
for xrefs in cross_references:
        encrypted_data = xrefs.mlil.params[0].constant
        encrypted_data_block = bv.read(encrypted_data, 200)
        if isinstance(encrypted_data_block, list):
            encrypted_data_block = bytes(encrypted_data_block)
        
        b64_str = encrypted_data_block.split(b'\x00\x00\x00\x00')
        set_str = b64_str[0]
        try:
            decode = base64.b64decode(set_str)
            hex_str = binascii.hexlify(decode)
            unhex_str = binascii.unhexlify(hex_str)           
            key_rc4 = binascii.unhexlify(rc4_key)
            rc4_init = Transform['RC4']
            rc4_decryption = rc4_init.decode(unhex_str, {'key':key_rc4})
            bv.set_comment_at(xrefs.address, rc4_decryption)
        except Exception as e:
            print(f"Error: {e}")

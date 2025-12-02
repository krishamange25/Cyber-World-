import os
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

long_plain_text_base = b"This is a secret message that is reasonably long for testing AES modes. "
long_plain_text = long_plain_text_base * 50 
                                        

AES_KEY_SIZE = 32
AES_BLOCK_SIZE = AES.block_size 
SNIPPET_LENGTH = 64

def print_snippet(label, data):
    if data is None:
        print(f"{label}: None")
        return
    
    display_data = data[:SNIPPET_LENGTH]
    ellipsis = b"..." if len(data) > SNIPPET_LENGTH else b""
    try:
       
        decoded_snippet = display_data.decode('utf-8', 'replace')
        print(f"{label} (first {SNIPPET_LENGTH} bytes): {decoded_snippet}{ellipsis.decode('utf-8', 'replace') if ellipsis else ''}")
    except: 
        print(f"{label} (first {SNIPPET_LENGTH} bytes, hex): {display_data.hex()}{ellipsis.hex() if ellipsis else ''}")


def perform_operation(key, mode, data, p_iv_or_nonce=None, p_tag=None, is_encrypt=True):
    if mode == AES.MODE_EAX:
        cipher = AES.new(key, mode, nonce=p_iv_or_nonce)
        if is_encrypt:
            return cipher.encrypt_and_digest(data)
        else:
            return cipher.decrypt_and_verify(data, p_tag)
    elif mode == AES.MODE_CTR:
        cipher = AES.new(key, mode, nonce=p_iv_or_nonce)
        return cipher.encrypt(data)
    elif mode == AES.MODE_OFB or mode == AES.MODE_CFB:
        cipher = AES.new(key, mode, iv=p_iv_or_nonce)
        return cipher.encrypt(data)
    elif mode == AES.MODE_CBC:
        cipher = AES.new(key, mode, iv=p_iv_or_nonce)
        if is_encrypt:
            return cipher.encrypt(pad(data, AES_BLOCK_SIZE))
        else:
            return unpad(cipher.decrypt(data), AES_BLOCK_SIZE)
    return None

modes_to_evaluate = [
    ("CBC", AES.MODE_CBC),
    ("CTR", AES.MODE_CTR),
    ("OFB", AES.MODE_OFB),
    ("CFB", AES.MODE_CFB),
    ("EAX", AES.MODE_EAX)
]

print(f"Plaintext length: {len(long_plain_text)} bytes")
print_snippet("Original Plaintext", long_plain_text)
print("\n" + "="*70)

print(f"\n{'Mode':<5} | {'Enc Time (s)':<15} | {'Dec Time (s)':<15} | {'Status':<10}")
print("-" * 55)

results_summary = {}

for mode_name, aes_mode_const in modes_to_evaluate:
    print(f"\n--- Testing Mode: {mode_name} ---")
    key = get_random_bytes(AES_KEY_SIZE)
    
    current_param_iv_nonce = None
    if aes_mode_const == AES.MODE_CTR:
        current_param_iv_nonce = get_random_bytes(8) 
    else:
        current_param_iv_nonce = get_random_bytes(AES_BLOCK_SIZE)
    
    print_snippet(f"IV/Nonce ({len(current_param_iv_nonce)} bytes, hex)", current_param_iv_nonce)

    ciphertext = None
    tag_eax = None
    decrypted_text = None
    status = "FAIL"

    start_enc = time.perf_counter()
    if aes_mode_const == AES.MODE_EAX:
        ciphertext, tag_eax = perform_operation(key, aes_mode_const, long_plain_text, p_iv_or_nonce=current_param_iv_nonce, is_encrypt=True)
        print_snippet("EAX Tag (hex)", tag_eax)
    else:
        ciphertext = perform_operation(key, aes_mode_const, long_plain_text, p_iv_or_nonce=current_param_iv_nonce, is_encrypt=True)
    end_enc = time.perf_counter()
    enc_time = end_enc - start_enc
    print_snippet("Ciphertext", ciphertext)


    start_dec = time.perf_counter()
    try:
        if aes_mode_const == AES.MODE_EAX:
            decrypted_text = perform_operation(key, aes_mode_const, ciphertext, p_iv_or_nonce=current_param_iv_nonce, p_tag=tag_eax, is_encrypt=False)
        else:
            decrypted_text = perform_operation(key, aes_mode_const, ciphertext, p_iv_or_nonce=current_param_iv_nonce, is_encrypt=False)
        
        if decrypted_text == long_plain_text:
            status = "OK"
        else:
            status = "MISMATCH"
    except ValueError as e:
        status = "VERIFY_ERR"
        print(f"Decryption/Verification Error: {e}")
    except Exception as e:
        status = "DEC_ERR"
        print(f"Decryption Error: {e}")
    end_dec = time.perf_counter()
    dec_time = end_dec - start_dec
    print_snippet("Decrypted Text", decrypted_text)

    results_summary[mode_name] = (enc_time, dec_time, status)
    print(f"{mode_name:<5} | {enc_time:<15.6f} | {dec_time:<15.6f} | {status:<10}")
    print("-" * 55)


print("\n" + "="*70)
print("Summary Table:")
print(f"{'Mode':<5} | {'Enc Time (s)':<15} | {'Dec Time (s)':<15} | {'Status':<10}")
print("-" * 55)
for mode_name, (enc_t, dec_t, stat) in results_summary.items():
    print(f"{mode_name:<5} | {enc_t:<15.6f} | {dec_t:<15.6f} | {stat:<10}")
print("-" * 55)

print("\nNote: For CBC, OFB, CFB, the IV must be sent with the ciphertext.")
print("For CTR and EAX, the nonce must be sent with the ciphertext.")
print("PyCryptodome's AES.MODE_CTR typically uses a nonce shorter than block size (e.g., 8 bytes for AES).")
print("IVs/Nonces must be unique per key, but need not be secret (except for OFB IV sometimes).")
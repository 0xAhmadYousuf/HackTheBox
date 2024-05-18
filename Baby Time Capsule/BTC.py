# BTC = Baby Time Capsule
# When ive solved this one secound time i have decided to make this repo, (UURN UnUsual Repo Note)
import sys
import json
from Crypto.Util.number import long_to_bytes
from pwn import remote
from sympy.ntheory.modular import crt
from sympy import root  # Import 'root' instead of 'nthroot'

def main(ip_address, port_number):
    conn = remote(ip_address, port_number)
    rem = list()
    num = list()
    for i in range(3):
        conn.sendline(b'Y')
        r = conn.recvline()
        data = r.decode()  # Decode the received data
        # Print received data for debugging
        print("Received data:", data)
        # Find the start of the JSON data
        start_index = data.find('{')
        json_data = data[start_index:]  # Extract JSON data starting from the first '{'
        # Parse JSON data
        req = json.loads(json_data)
        msg = req['time_capsule']
        pub = req['pubkey'][0]
        e = 5
        rem.append(int(msg, 16))
        num.append(int(pub, 16))
    x = crt(num, rem, check=True)
    # Use sympy's root function
    flag = root(x[0], 5)
    # Print the decrypted message
    print('\nFlag:', long_to_bytes(flag).decode())
    conn.sendline(b'N')
    conn.recvline()
    conn.close()

if __name__ == '__main__':
    ip_address = "83.136.251.226"
    port_number = 43555
    main(ip_address, port_number)

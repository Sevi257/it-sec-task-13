#!/usr/bin/env python3
import json

import requests

# Name of the cookie
COOKIE = "session"
MAC_SIZE = 4
def mh5(x):
    state = 0

    # Apply padding
    x = x + b"\x80"  # Terminate message with 0x80
    x = x + (MAC_SIZE - (len(x) % MAC_SIZE)) * b"\x00"

    # Split into chunks
    for i in range(0, len(x), MAC_SIZE):
        state += int.from_bytes(x[i:i + MAC_SIZE], byteorder="big")
        state &= (2 ** 32 - 1)
    return state.to_bytes(length=MAC_SIZE, byteorder="big")



# URL of the target server
url = "http://127.0.0.1:5000"

with requests.Session() as session:
    r = session.get(url)
    original_cookie = session.cookies[COOKIE]
    '''secret_key = bytes(original_cookie[:8].encode())
    test = '{"u": "admin"}'.encode()
    mac = mh5(secret_key + test)
    final = mac.hex() + test.hex()
    test2 = bytes.fromhex(final)
    mac, session_data = test2[:MAC_SIZE], test2[MAC_SIZE:]
    mac_p = mh5(secret_key + test)
    if mac_p == mac:
        print("Success")
    else:
        print("Failure")
        print(f"Integrity check failed {mac} {mac_p}")
    print(final)
    session.cookies.set(name=COOKIE, value=final, domain="http://127.0.0.1:5000")
    print(f'Values: {session.cookies.values()} and Keys: {session.cookies.keys()}')
    # 71a15f407b2275223a2022746573746572227d
    # 71a15f407b2275223a2022746573746572227d
    # Der Session cookie encoded tester also muss ich admin encoden mit MH5
    #
    # Step 4: Make a request with the modified cookie'''
    r = session.get(url)
    print(r.text)
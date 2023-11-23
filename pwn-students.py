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
url = "http://127.0.0.1:8080"

with requests.Session() as session:
    r = session.get(url)
    original_cookie = session.cookies[COOKIE]
    # ceef72fd7b7d -> Tester Value -> Muss das selbe sein
    # 3c2d80f1 -> Admin Value
    # ceef36cffa8c brauche ich noch

    print(bytes(original_cookie.encode()))
    #Add some padding or something
    test = '{"u": "admin"}'.encode()
    mac = mh5(test)

    print(mac.hex())
    session.cookies.set(name=COOKIE, value=test, domain="http://127.0.0.1:8080")
    print(f'Values: {session.cookies.values()} and Keys: {session.cookies.keys()}')
    # 71a15f407b2275223a2022746573746572227d
    # 71a15f407b2275223a2022746573746572227d
    # Der Session cookie encoded tester also muss ich admin encoden mit MH5
    #
    # Step 4: Make a request with the modified cookie
    #session.cookies.set(name=COOKIE, value="asdf", domain="http://127.0.0.1:5000")
    r = session.get(url)
    print(r.text)
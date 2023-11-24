#!/usr/bin/env python3
import json

import requests
import numpy

# Name of the cookie
COOKIE = "session"
MAC_SIZE = 4
def mh5(x):
    state = 0

    x = x + b"\x80"
    x = x + (MAC_SIZE - (len(x) % MAC_SIZE)) * b"\x00"
    # Split into chunks
    for j in range(0, len(x), MAC_SIZE):
        state += int.from_bytes(x[j:j + MAC_SIZE], byteorder="big")
        state &= (2 ** 32 - 1)
    return state.to_bytes(length=MAC_SIZE, byteorder="big")


url = "https://t13.itsec.sec.in.tum.de/950357d650d4fa78"
#url = "http://127.0.0.1:5000"

with requests.Session() as session:
    r = session.get(url)
    original_cookie = session.cookies[COOKIE]
    # ceef72fd7b7d -> Tester Value -> Muss das selbe sein
    # 3c2d80f1 -> Admin Value
    # ceef36cffa8c brauche ich noch

    print(original_cookie.encode())
    #Add some padding or something
    #71a15f40 7b2275223a2022746573746572227d
    #data = mac.hex() + session_json.hex()
    #mac.hex() = 4Bytes ersten 4 Bytes sind mac und danach ist encoded mit Tester
    # Man muss das json objekt so erstellen dass es zu dem selben Mac auswertet und dass es insgesamt der gleiche Hash ist
    # erstelle das richtige mac_p
    # mh5(secretkey + sessiondata) = mac
    # '{"u": "admin", }'
    mac = original_cookie[:8]
    print("MAC: ", mac)
    jsondump = original_cookie[8:]

    i = 0
    while True:
        test_data = ('{"u": "admin", "extra_data": "' + str(i) + '"}').encode()
        test_mac = mh5(test_data)
        #print("Testmac: ", test_mac)
        if test_mac.hex() == mac:
            print(f"Collision found! i={i}, test_data={test_data}")
            break
        if i == 65536:
            print("50%")
        if i == 2147483648:
            print("Unlikely")
        i += 1

    testtest = json.loads(bytes.fromhex(test_data.hex()))
    session.cookies.set(name=COOKIE, value=test_data.hex(), domain="https://t13.itsec.sec.in.tum.de/9")
    print(f'Values: {session.cookies.values()} and Keys: {session.cookies.keys()}')
    r = session.get(url)
    print(r.text)
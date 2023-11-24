#!/usr/bin/env python3
import json

import requests
import numpy

# Name of the cookie
COOKIE = "session"
MAC_SIZE = 4
def mh5(x, mac):
    state = 0

    # Apply padding
    #x = x + b"\x80"  # Terminate message with 0x80
    # 2 Zeichen waren noch frei aber eines davon ist 0x80
    # Es wird echt viel dann wenn man appended
    # Man kann nur Bytes appenden aber die müssen den richtigen Wert haben -> wie kann man das ausrechnen
    # Mit einem for loop über valid bytes drübergehen und wenn es dann a
    # Bis auf einen Block auffüllen dann bytes.fromHex(Differenz) dann anhängen
    # Zusammenhang mit Secret Key
    print("Padding: ", (MAC_SIZE - (len(x) % MAC_SIZE)))
    x = x
    x = x + (MAC_SIZE - (len(x) % MAC_SIZE)) * b"\x00"
    # Split into chunks
    for i in range(0, len(x), MAC_SIZE):
        state += int.from_bytes(x[i:i + MAC_SIZE], byteorder="big")
        state &= (2 ** 32 - 1)
    return state.to_bytes(length=MAC_SIZE, byteorder="big")


url = "https://t13.itsec.sec.in.tum.de/950357d650d4fa78"

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
    print(mac)
    jsondump = original_cookie[8:]

    test = '{"u": "admin", "t": "Hel2ë|$lo"}'.encode()
    mac_p = mh5(test, mac)
    print(mac_p.hex())
    testtest = json.loads(bytes.fromhex(test.hex()))
    print(testtest)
    test =  b"1111aaaa" + test
    session.cookies.set(name=COOKIE, value=test.hex(), domain="https://t13.itsec.sec.in.tum.de/")
    print(f'Values: {session.cookies.values()} and Keys: {session.cookies.keys()}')
    r = session.get(url)
    print(r.text)
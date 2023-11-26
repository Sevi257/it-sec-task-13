#!/usr/bin/env python3
import json

import requests

# Name of the cookie
COOKIE = "session"
MAC_SIZE = 4
def mh5(x):
    state = 0

    x = x + b"\x80"
    x = x + (MAC_SIZE - (len(x) % MAC_SIZE)) * b"\x00"
    # Split into chunks
    print((MAC_SIZE - (len(x) % MAC_SIZE)))
    for j in range(0, len(x), MAC_SIZE):
        state += int.from_bytes(x[j:j + MAC_SIZE], byteorder="big")
        state &= (2 ** 32 - 1)
    return state.to_bytes(length=MAC_SIZE, byteorder="big")

def calc(res, xminus1, xplusone):
    first = res - xplusone
    print(f'RES: {res}, XMINUS: {xminus1}, XPLUS: {xplusone}, first {first + 2**32}')
    if first < 0:
        first += 2**32
    print("AGain: ", first-xminus1)
    if first-xminus1 < 0:
        return first - xminus1 + 2**32
    else:
        return first - xminus1
def mh5test(x, y):
    state = 0

    # Apply padding
    x = x + b"\x80"  # Terminate message with 0x80
    x = x + (MAC_SIZE - (len(x) % MAC_SIZE)) * b"\x00"
    y = y + b"\x80"  # Terminate message with 0x80
    y = y + (MAC_SIZE - (len(y) % MAC_SIZE)) * b"\x00"
    diff = 0
    # print(x)
    state2 = 0

    # Split into chunks
    for i in range(0, len(x), MAC_SIZE):
        print(x[i:i + MAC_SIZE])
        print(y[i:i + MAC_SIZE])
        state += int.from_bytes(x[i:i + MAC_SIZE], byteorder="big")
        state2 += int.from_bytes(y[i:i + MAC_SIZE], byteorder="big")
        diff += (int.from_bytes(x[i:i + MAC_SIZE], byteorder="big") - int.from_bytes(y[i:i + MAC_SIZE],
                                                                                     byteorder="big"))
        print(str(diff) + "Diff")
        state &= (2**32 - 1)
        state2 &= (2**32 - 1)
        print("STATE :" + str(state))
        print("STA   :" + str(state2))
        print("STAT  :" + str((state2 + diff) & 2 ** 32 - 1))
        print(hex(int(diff)) + " final diff")

    #mod = y + diff.to_bytes(length=MAC_SIZE, byteorder="big", )

    return state.to_bytes(length=MAC_SIZE, byteorder="big")
#url = "https://t13.itsec.sec.in.tum.de/950357d650d4fa78"
url = "localhost"
with requests.Session() as session:
    r = session.get(url)
    original_cookie = session.cookies[COOKIE]
    # ceef72fd7b7d -> Tester Value -> Muss das selbe sein
    # 3c2d80f1 -> Admin Value
    # ceef36cffa8c brauche ich noch

    print(original_cookie.encode())
    mac = original_cookie[:8]
    print("Original Mac: ", mh5(b'{"u": "tester"}').hex())

    test_data = b'{"u": "admin", "zata": "\x4d\x3e\x56\x65g"}'
    test_mac = mh5(test_data).hex()
    print("Selfmade mac: ", test_mac)

    print("Mac: ", mac)
    print(test_data.hex())

    mh5test(b'{"u": "admin", "zata": "\x4d\x3e\x56\x65g"}', b'{"u": "tester"}')

    final = mac + test_data.hex()
    session.cookies.set(name=COOKIE, value=final, domain="localhost")
    print(f'Values: {session.cookies.values()} and Keys: {session.cookies.keys()}')
    q = session.get(url)
    print(q.text)

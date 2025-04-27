#!/usr/bin/python3
# Testing script for the server
# Clear the database before running this.

import base64, binascii, traceback

# pip install requests
import requests

URL = 'http://127.0.0.1:9090/?action='

class State:
    def __init__(self):
        self.username = 'abcdef'
        self.password = 'a' * 128
        self.token = None
        self.passwords = 0
        self.users = 0
        self.passwords_list = []
    def getAuth(self, password):
        return 'Basic ' + base64.b64encode((self.username + ':' + password).encode()).decode()
tests = []
def Test(fn):
    tests.append(fn)
    return fn

def assertSuccessful(r):
    print(r.text)
    assert r.status_code == 200
    assert r.json()['error'] == 0
    assert r.json()['info'] == 'Successful'


@Test
def get_info(state):
    r = requests.get(URL + 'getInfo')
    print(r.text)
    assert r.status_code == 200
    assert r.json()['passwords'] == state.passwords
    assert r.json()['users'] == state.users
    assert 'version' in r.json()

# files={'dummy': ''} is to force multipart/form-data into requests
@Test
def create_account(state):
    r = requests.post(URL + 'createAccount', headers={'Authorization':  state.getAuth(state.password)}, data={'email': 'abcdef@host.local'}, files={'dummy': ''})
    assertSuccessful(r)
    state.users += 1

Test(get_info)

@Test
def get_token(state):
    r = requests.post(URL + 'getToken', headers={'Authorization': state.getAuth(state.password)})
    print(r.text)
    assert r.status_code == 200
    assert len(binascii.unhexlify(r.json()['token'])) == 32
    old_token = state.token
    state.token = r.json()['token']
    if old_token == None:
        assert r.json()['error'] == 8
        assert r.json()['info'] == 'You do not have any saved password.'
        assert 'passwords' not in r.json()
    else:
        if old_token != state.token:
            print('!'*30, 'WARNING', 'old_token != state.token')
        assertSuccessful(r)
        assert r.json()['passwords'] == state.passwords_list

@Test
def save_password(state):
    print('!'*30, 'NOT IMPLEMENTED')
    pass

@Test # Last test
def delete_account(state):
    r = requests.post(URL + 'deleteAccount', headers={'Authorization': state.getAuth(state.token)})
    assertSuccessful(r)
    state.passwords = 0
    state.users = 0

Test(get_info) # OK. this is the last one

state = State()
ok = True
for test in tests:
    print('*'*5, 'TEST:', test.__name__, '*'*5)
    try:
        test(state)
        print('*'*5, 'PASS', '*'*5)
    except Exception as e:
        ok = False
        if test == create_account or test == get_info:
            traceback.print_exc()
            print('!' * 20, 'FAIL', '!' * 20)
            continue
        if state.users != 0:
            print('Cleaning up...')
            delete_account(state)
        raise e
if ok:
    print('='*30, 'All tests passed!', '='*30)
else:
    print(':(')

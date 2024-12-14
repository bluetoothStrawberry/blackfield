#!/usr/bin/env python3
import subprocess
import shlex
import sys

target = 'dc01' # HTB's dc01.blackfield.local box

username = 'guest'
password = '' 
max_rid = 1500

def get_sid(target: str, username: str, password: str ) -> str:
    lsaquery = f'/usr/bin/rpcclient -U {username}%{password} -c "lsaquery" {target}'
    try:
        sid = subprocess.check_output(shlex.split(lsaquery)).decode().strip().split()[-1]
    except:
        pass
    if 'S-' not in sid:
        return None
    return sid


def get_objects(sid: str, max_rid: int, target: str, username: str, password: str) -> tuple:
    groups , machines , users = [], [], []
    sids = ' '.join([ f'{sid}-{str(rid)}' for rid in range(500, max_rid + 1)])
    lookupsids = f'/usr/bin/rpcclient -U {username}%{password} -c "lookupsids {sids}" {target}'
    try:
        res = subprocess.check_output(shlex.split(lookupsids)).decode()
    except:
        pass
    if 'administrator' not in res.lower():
        return [], [], []
    for line in res.split('\n'):
        if '(2)' in line or '(4)' in line:
            groups.append(' '.join(line.split(' ')[:-1][1:]))
        if '(1)' in line and '$' in line:
            machines.append(line.split(' ')[-2])
        if '(1)' in line and '$' not in line:
            users.append(line.split(' ')[-2])
    return groups, machines, users


if __name__ == '__main__':
    sid = get_sid(target, username, password)
    groups, machines, users = get_objects(sid, max_rid, target, username, password)

    for group in groups:
        print(f'Group: {group}')
    for machine in machines:
        print(f'Machine: {machine}')
    for user in users:
        print(f'User: {user}')

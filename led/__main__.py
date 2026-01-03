'''
    A CLI for controlling the power state of the Lepro S1 LED 5m strip.
    The goal is to automatically control the state of the strip, e.g.
    combine this script with shell:startup to activate the strip on boot.

    Usage:
        py main.py --update       # Setup the replay. Run this first.
        py main.py --power on/off # Toggle the strip power.
    
    I originally intended to reverse engineer the whole coms between the
    Lepro app and the strip for advanced color control, but screw this,
    I don't have time for a stupid strip that I don't even use that often.
    The Lepro app is very annoying to use, and the data structure looks
    encrypted or ofbuscated or I don't fucking know I am not a bluetooth
    dev, so BLE packet replay it is.

    Every time you cut power to the strip, you need to toggle the power
    switch a few times on your phone in the app (end with ON), then plug
    the phone to your PC and run the update command.

    The update command assumes your phone:
    - Has bluetooth HCI logs enabled;
    - Accepts ADB connections from your PC systematically;
    - Is rooted and the ADB shell has root permissions;
    - The HCI file is located in /data/log/bt (for most Samsung phones).
'''

import os
import time
import bleak
import asyncio
import pyshark
import argparse
from ppadb.client import Client
from ppadb.device import Device

ADDRESS = 'fc:01:2c:c2:a6:ba'
SERVICE = '1e2aa502-7292-4263-a8f1-be907f039a1f'
REPLAY = os.path.join(os.path.dirname(__file__), 'replay')

def update() -> None:
    '''
    Update the commands.txt file.
    
    Usage - Before running, toggle a few times the ON/OFF switch
    in the app. Ensure to end the sequence with ON.
    
    The phone must:
    - Be rooted
    - Be already linked to this PC via ADB
    - Authorize the ADB shell to use root
    - Have HCI snoop already activated
    '''

    print('Starting ADB server')
    os.system('adb start-server')

    print('Connecting to phone')
    adb: Device = Client().devices()[0]

    print('Pulling HCI')
    adb.shell('su -c "cp /data/log/bt/btsnoop_hci.log /sdcard/hci.log"')
    adb.pull('/sdcard/hci.log', 'hci.log')

    print('Analysing HCI')
    capture = pyshark.FileCapture('hci.log', use_json = True, include_raw = True)

    instructions: list[str] = []

    for packet in capture:
        # Filter out packets
        try:
            assert packet.BTHCI_ACL.dst.bd_addr == ADDRESS
        except:
            continue

        payload = packet.get_raw_packet().hex()

        if len(payload) != 108: continue

        instructions.append(payload)

        if len(instructions) > 2:
            instructions.pop(0)
    
    assert len(instructions) == 2, 'Commands not found'
    
    print('Cleaning up')
    with open(REPLAY, 'w') as file:
        file.write('\n'.join(instructions))
    
    os.remove('hci.log')

async def send(command: str) -> None:
    '''
    Send an HEX command to the device.
    '''

    start = time.time()
    print('Connecting to device')
    client = bleak.BleakClient(ADDRESS, timeout = 60, pair = True)
    await client.connect(timeout = 60)

    print('Sending instruction')
    await client.write_gatt_char(SERVICE, bytes.fromhex(command))

    await client.disconnect()
    print(f'Instruction sent in {time.time() - start}s')

if __name__ == '__main__':

    parser = argparse.ArgumentParser('strip')
    parser.add_argument('--power')
    parser.add_argument('--update', action = 'store_true')

    args = parser.parse_args()

    if args.update:
        update()
        exit()
    
    if not args.power:
        print('Hi.')
        exit()

    assert os.path.exists(REPLAY), 'Run updater first'
    
    with open(REPLAY) as file:
        command = file.read().split()[args.power in ('on', '1')]
    
    # Send command
    asyncio.run(send(command))

# EOF
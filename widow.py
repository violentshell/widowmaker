import time, threading, sys, os, random
from scapy.all import *
from termcolor import colored
import select
import pyric.pyw as pyw

def ap_gen(SSID):
    # Default 802.11 beacon packet, probably use the ap's with fake data to adapt better to changing networks TODO
    ap_pkt = RadioTap(version = 0, pad = 0, len = 18, present = 'Flags+Rate+Channel+dBm_AntSignal+Antenna+b14', notdecoded= '\x00\x02\x99\t\xa0\x00\xbf\x01\x00\x00')
    ap_pkt = ap_pkt/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())
    ap_pkt = ap_pkt/Dot11Beacon(cap='ESS')/Dot11Elt(ID="SSID", info=SSID+'1')
    ap_pkt = ap_pkt/Dot11Elt(ID="Rates", info="/\x82\84\x0b\x16\"")/Dot11Elt(ID="DSset", info='\x03')/Dot11Elt(ID="TIM", info='\x00\x01\x00\x00')

    # Loop while the thread is active, sending at rate
    while True:
        time.sleep(rate)
        sendp(ap_pkt, count=1, iface="wlan0mon", verbose=False)

#outside class because scapy doesn't play nice with self



def sniffer(mode, minchannel, maxchannel):
    card = pyw.getcard('mon0')
    while mode == 'Scanning':
        channel = random.randint(minchannel, maxchannel)
        pyw.chset(card, channel)
        sniff(iface='mon0', prn=filter, timeout=0.3)
        return channel

def filter(pkt):
    if pkt.haslayer(Dot11Elt) and pkt[Dot11].type == 0 and pkt[Dot11].subtype in [5,8,11]:
            SSID = (pkt[Dot11Elt].info).decode('utf-8')
            if SSID != None and SSID != "" : #Testing purposes "and SSID[-1] != '1':"
                if SSID not in clients.keys():

                    # Setup counters
                    clients[SSID]['#'] = len(clients) +1
                    clients[SSID]['Probes'] = 0
                    clients[SSID]['Beacons'] = 0
                    clients[SSID]['Auth'] = 0
                    clients[SSID]['Total'] = 0

                    # Capture MAC addresses
                    clients[SSID]['MAC'] = pkt[Dot11].addr2

                    # Generate a random one too, Is this needed?
                    clients[SSID]['RMAC'] = str(RandMAC())

                    # Add the pkt for debugging
                    clients[SSID]['PKT'] = pkt
                elif pkt[Dot11].subtype == 5:
                    clients[SSID]['Probes'] +=1
                elif pkt[Dot11].subtype == 8:
                    clients[SSID]['Beacons'] +=1
                elif pkt[Dot11].subtype == 11:
                    clients[SSID]['Auth']  +=1
                clients[SSID]['Total'] += 1


class Vividict(dict):
    def __missing__(self, key):
        value = self[key] = type(self)()
        return value

class widow():
    def __init__(self):
        self.wireless = pyw.getcard(sys.argv[1])
        self.channel = 1
        self.minchannel = 1
        self.maxchannel = 13
        self.timeout = 5
        self.monfaces = []
        self.mode = 'Scanning'
        self.interface = 'mon0'
        self.interface_setup()

    def interface_setup(self):
        print('setting up interfaces')
        if pyw.isinterface(self.interface):
            pyw.devdel(pyw.getcard(self.interface))
        pyw.devadd(self.wireless, self.interface,'monitor')
        card = pyw.getcard(self.interface)
        pyw.chset(card, self.channel)
        pyw.up(card)

    def scanner(self):
        while self.mode == 'Scanning':
            try:
                self.printer()
                self.channel = sniffer(self.mode, self.minchannel, self.maxchannel)
            except KeyboardInterrupt:
                self.mode = 'Select'
        while self.mode == 'Select':
            try:
                self.printer()
                i, o, e = select.select([sys.stdin], [], [], 0.5)
                self.target = int(sys.stdin.readline().strip())
                for i in clients:
                    if clients[i]['#'] == self.target:
                        self.target = i
                        break
                    else:
                        self.target = None
                if self.target == None:
                    print(colored('[!] Invalid Target Choice, Try Again' , 'red'))
                    time.sleep(1.5)
                else:
                    self.mode = 'Hunting'
                    self.hunting()

            except KeyboardInterrupt:
                self.mode = 'None'

    def hunting(self):
        self.printer()
        t = threading.Thread(target=ap_gen, args=(self.target,))
        t.daemon = True
        t.start

    def printer(self):
        #TODO, allow SSID selection on the fly. Then spin up new spoofing engines
        # Clear the screen whenever we print
        os.system('clear')


        # Terminal size
        rows, columns = os.popen('stty size', 'r').read().split()

        # Print the Banner
        for bannerline in banner.splitlines():
            print(colored('{} {}', 'green').format(' '*(round(int(columns)/2-35)), bannerline))

        # Print the info summary
        print('#'*int(columns))
        print(colored('CURRENT STATUS: {} {}','blue').format(self.mode, '[CTRL-C TO STOP]'))

        # Each Mode
        if self.mode == 'Scanning':
            print(colored('[*] Current Channel: {}', 'green').format(self.channel))
            print('#' * int(columns))
            print(colored('SSID:\t\t\t' + 'MAC:\t\t\t'  + 'FRAMES:\t\t\t','blue'))

        elif self.mode == 'Select':
            print('#' * int(columns))
            print(colored('[*] Please make a selection from the below SSIDs:', 'green'))
            print(colored('SSID:\t\t\t' + 'MAC:\t\t\t', 'blue'))

        elif self.mode == 'Hunting':
            print(colored('[*] Beacon Frame Rate: \t\t\t {} frames p/s', 'green').format(rate * int(sys.argv[2])))
            print(colored('[*] Target Access Point: \t\t ' + self.target, 'green'))
            print('#' * int(columns))
            print(colored('TARGET:\t\t\t' + 'MAC:\t\t\t' + 'FAKE MAC:\t\t\t', 'blue'))
        self.client_tab_foo()

    def client_tab_foo(self):
        for i in sorted(clients):
            # Tab foo!
            if len(str(i)) <= 3:
                tab = 3
            elif len(str(i)) <= 10:
                tab = 2
            elif len(str(i)) <= 15:
                tab = 1
            else:
                tab = 0

            if self.mode == 'Scanning':
                print(colored('[{}] {} {} {} {} {}', 'red').format(clients[i]['#'], i, '\t'*tab, clients[i]['MAC'],'\t', clients[i]['Total']))

            elif self.mode =='Select':
                print(colored('[{}] {} {} {} ','red').format(clients[i]['#'], i, '\t'*tab, clients[i]['MAC']))

            elif self.mode == 'Hunting' and i == self.target:
                print(colored('{} {} {} {} {}', 'red').format(i, '\t' * tab, clients[i]['MAC'], '\t', clients[i]['RMAC']))


# Setup dicts for later use
global rate, clients, number


# Dear lord this is ugly.
banner = ''' __    __ _     _                              _
/ / /\ \ (_) __| | _____      __   /\/\   __ _| | _____ _ __
\ \/  \/ / |/ _` |/ _ \ \ /\ / /  /    \ / _` | |/ / _ \ '__|
 \  /\  /| | (_| | (_) \ V  V /  / /\/\ \ (_| |   <  __/ |
  \/  \/ |_|\__,_|\___/ \_/\_/   \/    \/\__,_|_|\_\___|_|
  '''


try:
    interf = sys.argv[1]
except:
    sys.exit(colored('[!] Need interface', 'red'))


# Sets custom rate or uses default perhaps TODO
try:
    rate = float(60)/int(sys.argv[2])
except:
    sys.exit(colored('[!] Need rate', 'red'))

# Basically a loading screen. Actually, add a proper loading bar in later TODO
number = 0
clients = Vividict()
main = widow()
main.scanner()
# try:
#     # Sniff on said interface and send packets to the filtering engine
#     main.scanner()
#
# except(KeyboardInterrupt, SystemExit):
#     # Something terrible has happened, please not the ascii art
#     print('Goodbye')
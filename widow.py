import time, threading, sys, os, random
from scapy.all import *
from termcolor import colored
import select
import pyric.pyw as pyw

def ap_gen(SSID, real_mac):
    # Default 802.11 beacon packet, probably use the ap's with fake data to adapt better to changing networks TODO
    ap_pkt = RadioTap(version = 0, pad = 0, len = 18, present = 'Flags+Rate+Channel+dBm_AntSignal+Antenna+b14', notdecoded= '\x00\x02\x99\t\xa0\x00\xbf\x01\x00\x00')
    ap_pkt = ap_pkt/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())
    ap_pkt = ap_pkt/Dot11Beacon(cap='ESS')/Dot11Elt(ID="SSID", info=SSID)
    ap_pkt = ap_pkt/Dot11Elt(ID="Rates", info="/\x82\84\x0b\x16\"")/Dot11Elt(ID="DSset", info='\x03')/Dot11Elt(ID="TIM", info='\x00\x01\x00\x00')

    # Loop while the thread is active, sending at rate
    while True:
        time.sleep(rate)
        sendp(ap_pkt, count=1, iface="wlan0mon", verbose=False)

#outside class because scapy doesn't play nice with self
def filter(pkt):
    print(pkt.Summary)
    try:
        # Count total 802.11 packets TODO Make this a filter function
        packet.haslayer(Dot11Elt)
        print('802.11')
        ssidprocess()
    except:
        # If it's not 802.11 we are done here. Scapy filter doesnt always do these things cleanly.
        return


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
        self.clients = Vividict()
        self.mode = 'Scanning'
        self.interface = 'mon0'
        self.interface_setup()
        print('init complete')

    def interface_setup(self):
        print('setti    ng up interfaces')
        if pyw.isinterface(self.interface):
            pyw.devdel(pyw.getcard(self.interface))
        pyw.devadd(self.wireless, self.interface,'monitor')
        card = pyw.getcard(self.interface)
        pyw.chset(card, self.channel)
        pyw.up(card)

    def sniff(self):
        while self.mode == 'Scanning':
            card = pyw.getcard('mon0')
            self.channel = random.randint(self.minchannel, self.maxchannel)
            pyw.chset(card, self.channel)
            sniff(iface='mon0', prn=filter(), timeout=0.5)

    def ssidprocess(self):
        try:
            SSID = packet[Dot11Elt].info
            # TODO add frametypes = [0,2,4]

            # What is this?
            if SSID != None and SSID != "" and SSID[-1] != '1':
                if SSID not in self.clients.keys():

                    # Capture MAC addresses
                    self.clients[SSID]['MAC'] = packet[Dot11].addr2

                    # Generate a random one too
                    self.clients[SSID]['RMAC'] = RandMAC()
                    # Start spoofing engine thread
                    # t = threading.Thread(target=ap_gen, args=(SSID,))
                    # t.daemon = True
                    # t.start()

        except Exception as e:
            # print e
            pass

    def scanner(self):
        print('in scanner')
        t = threading.Thread(target=self.sniff, args=())
        t.daemon = True
        t.start()
        while self.mode == 'Scanning':
            #self.printer()
            #sys.stdin.flush()
            pass
            i, o, e = select.select([sys.stdin], [], [], 0.5)
            try:
                self.target = sys.stdin.readline().strip()
                self.target = int(self.target)
                self.mode = 'Hunting'
                answer = None
                self.hunting()
            except:
                pass

    def hunting(self):
        print('hunt')
        self.printer()

    def printer(self):
        #TODO, allow SSID selection on the fly. Then spin up new spoofing engines
        # Clear the screen whenever we print
        os.system('clear')

        # Write back here later to change terminal size
        rows, columns = os.popen('stty size', 'r').read().split()

        # Print the Banner
        for bannerline in banner.splitlines():
            print(colored('{} {}', 'green').format(' '*(round(int(columns)/2-35)), bannerline))

        # Print the info summary
        print('#'*int(columns))
        print(colored('CURRENT STATUS: {}','blue').format(self.mode))
        if self.mode == 'Scanning':
            try:
                print(colored('[*] Current Channel: {}', 'green').format(self.channel))
                print('#' * int(columns))
                print(colored('AVAILABLE TARGETS:\t\t\t\t' + 'REAL MAC:\t\t\t', 'blue'))
                self.client_tab_foo()
            except:
                pass
        else:
            print(colored('[*] Beacon Frame Rate: \t\t\t {} p/s', 'green').format(rate * int(sys.argv[2])))
            print(colored('[*] Beacon Frame Throughput: \t\t {} p/s', 'green').format(rate * int(sys.argv[2]) * len(clients)))
            print(colored('[*] Total Access Points: \t\t ' + str(len(clients)), 'green'))
            print('#'*int(columns))
            print(colored('AVAILABLE TARGETS:\t\t\t' + 'REAL MAC:\t\t\t' + 'FAKE MAC:\t\t\t\t', 'blue'))
            self.client_tab_foo()



    def client_tab_foo(self):# All the data's
        for n,i in enumerate(clients_real):
            # Tab foo!

            if len(str(i)) <= 3:
                tab = 6
            elif len(str(i)) <= 10:
                tab = 5
            elif len(str(i)) <= 15:
                tab = 3
            else:
                tab = 2

            #print(self.mode, n, self.target)
            if self.mode == 'Scanning':
                print(colored('[{}] {} {} {} ', 'red').format(n, i, '\t'*tab, clients_real[i]))

            elif self.mode =="Hunting" and self.target == n:
                print(colored('[{}] {} {} {} {} {} ','red').format(n,i,'\t'*tab, clients_real[i], '\t\t', clients[i]))

# Setup dicts for later use
global rate


# Dear lord this is ugly.
banner = ''' __    __ _     _                              _
/ / /\ \ (_) __| | _____      __   /\/\   __ _| | _____ _ __
\ \/  \/ / |/ _` |/ _ \ \ /\ / /  /    \ / _` | |/ / _ \ '__|
 \  /\  /| | (_| | (_) \ V  V /  / /\/\ \ (_| |   <  __/ |
  \/  \/ |_|\__,_|\___/ \_/\_/   \/    \/\__,_|_|\_\___|_|
  '''

# This will prob be wlan0mon or mon0
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
# loading, as per reddit post
main = widow()

try:
    # Sniff on said interface and send packets to the filtering engine
    main.scanner()

except(KeyboardInterrupt, SystemExit):
    # Something terrible has happened, please not the ascii art
    print('Goodbye')

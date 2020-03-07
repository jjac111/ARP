#This code is based on https://null-byte.wonderhowto.com/how-to/build-arp-scanner-using-scapy-and-python-0162731/
import sys
from datetime import datetime
from scapy.all import srp, Ether, ARP, conf
from mac_vendor_lookup import MacLookup

if __name__ == "__main__":

    try:
        interface = input("Enter desired interface: ")
        ips = input("Enter range of IPs to Scan for: ")

    except KeyboardInterrupt:
        print ("\n User requested shutdown")
        print ("Quiting...")
        sys.exit(1)

    print ("\n Scanning... ")
    start_time = datetime.now()

    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips), timeout=15, iface=interface, verbose=False)

    #print ans.summary()
    print ('MAC - IP')
    for s, r in ans:
        print (r.sprintf(r'%Ether.hwsrc% - %ARP.psrc%'))

    stop_time = datetime.now()
    total_time = stop_time - start_time
	
    print ("\n Scan Complete!")
    print ("Scan Duration: %s" %(total_time))
    print()

    ML = MacLookup()
    for a in ans:
        mac = a[1].hwsrc
        print(ML.lookup(mac))
#This code is based on https://null-byte.wonderhowto.com/how-to/build-arp-scanner-using-scapy-and-python-0162731/
import sys
import os
import platform
from datetime import datetime, date
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
	
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips), timeout=60, iface=interface, verbose=False)
	
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
	
	to_write = []
	
	for a in ans:
		mac = a[1].hwsrc
		ip = a[1].psrc
		try:
			lkup = ML.lookup(str(mac))
			to_write.append((ip, mac, lkup))
			print(lkup)
		except Exception as e:
			print(e)
			to_write.append((ip, mac, "U N K N O W N"))
			
	filename = "AROSEMENA_AYALA_" + ('WLAN' if interface == 'Wi-Fi' else 'LAN') + '_' + str(stop_time.year) + '.' + str(stop_time.month) + '.' + str(stop_time.day) + '.' + str(stop_time.hour) + '.' + str(stop_time.minute) + '.' + str(stop_time.second) + '.txt'
	directory = 'results'
	
	if not os.path.exists(directory):
		os.makedirs(directory)
	
	with open(directory + '/' + filename, 'w') as f:
		string = ""
		for ip, mac, lkup in to_write:
			string += f"{ip}\t{mac}\t{lkup}\n"
			
		f.write(string)
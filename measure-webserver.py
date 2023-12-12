#Aarsh Dadan : and126
#Command to start server: python3 measure-webserver.py pcap1.pcap 93.184.216.34 80

from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import TCP, IP
from scapy.all import *
import sys

def start(sessions, sIP, sPort):
    http_requests = {}
    response_times = []
    for session in sessions:
        for pkt in sessions[session]:
            if pkt.haslayer(HTTP):
                sourceIP = pkt[IP].src
                destIp = pkt[IP].dst
                if HTTPRequest in pkt:
                    if str(pkt[IP].dst) == sIP and str(pkt[TCP].dport) == sPort:
                        aTime = pkt.time
                        reqInfo = (aTime, destIp, pkt)
                        reqID = (sourceIP, destIp, pkt[IP].sport)
                        http_requests[reqID] = reqInfo
                elif HTTPResponse in pkt:
                    repID = (destIp, sourceIP, pkt[IP].dport)
                    if repID in http_requests and (str(pkt[IP].src) == sIP and str(pkt[TCP].sport) == sPort):
                        repInfo = (pkt.time, sourceIP, pkt)
                        reqInfo = http_requests[repID]
                        timDiff = float(repInfo[0] - reqInfo[0])
                        response_times.append(timDiff)
                        del http_requests[repID]
        latency = sum(response_times) / len(response_times)
        #Testing
        #print(f{response_times})
        #print("---------")
        print(f"AVERAGE LATENCY: {latency}")
        date = sorted(response_times)
        n = len(date)
        index25th = int(0.25 * n)
        index50th = int(0.50 * n)
        index75th = int(0.75 * n)
        index95th = int(0.95 * n)
        index99th = int(0.99 * n)
    
        a = date[index25th]
        b = date[index50th]
        c = date[index75th]
        d = date[index95th]
        e = date[index99th]
        print(f"PERCENTILES: {a} {b} {c} {d} {e}")
        
       

def main():
    if len(sys.argv) != 4:
        print("USAGE: python3 measurewebserver.py [input-file] [server-ip] [server-port]")
        sys.exit(1)
        
    load_layer("http")
    processed_file = rdpcap(sys.argv[1])
    sessions = processed_file.sessions()

    start(sessions, sys.argv[2], sys.argv[3])

if __name__ == "__main__":
    main()
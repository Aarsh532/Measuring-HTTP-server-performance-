#Aarsh Dadan : and126
#Command to start server: python3 measure-webserver.py pcap1.pcap 93.184.216.34 80

import numpy as np
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import TCP, IP
from scapy.all import *
import sys

def start(sessions, sIP, sPort):
    http_requests = {}
    responseTime = []
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
                        responseTime.append(timDiff)
                        del http_requests[repID]
        latency = sum(responseTime) / len(responseTime)
        #Testing
        #print(f{responseTime})
        #print("---------")
        print(f"AVERAGE LATENCY: {latency}")
        data = sorted(responseTime)
        a = data[int(0.25 * len(data))]
        b = data[int(0.50 * len(data))]
        c = data[int(0.75 * len(data))]
        d = data[int(0.95 * len(data))]
        e = data[int(0.99 * len(data))]
        print(f"PERCENTILES: {a} {b} {c} {d} {e}")
        klResult = computeKL(responseTime)
        print(f"KL DIVERGENCE: {klResult}")
       
def computeKL(input):
    meanLatency = np.mean(input)
    buckets = 10
    measuredDist = computeDist (input, meanLatency, buckets)
    buckEdge  = np.linspace(0, max(input), buckets + 1)
    theoreticalDist  = computeTDist(buckEdge , meanLatency)
    kl_divergence = sum(p * np.log2(p / q) for p, q in zip(measuredDist, theoreticalDist ) if p > 0 and q > 0)
    return kl_divergence

def computeDist (input, meanLatency, buckets=10):
        buckEdge  = np.linspace(0, max(input), buckets + 1)
        buckEdge [buckets] = float('inf')
        buckCounter, _ = np.histogram(input, bins=buckEdge )
        totalCount = sum(buckCounter)
        return [count / totalCount for count in buckCounter]
    
def computeTDist(buckEdge , meanLatency):
        mDistribution = []
        for i in range(len(buckEdge ) - 1):
            Lbound = buckEdge [i]
            uBound = buckEdge [i + 1] if i != len(buckEdge ) - 2 else float('inf')
            mass = (1 - np.exp(-(1.0 / meanLatency) * uBound)) - (1 - np.exp(-(1.0 / meanLatency) * Lbound))
            mDistribution.append(mass)
        return mDistribution
    
    
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
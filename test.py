import scapy
from scapy.all import Ether, IP, UDP, TCP, Dot1Q, Dot3, IPv6        # Ethernet type, format
from scapy.all import hexdump                                       # Dump Ethernet frame create
from scapy.utils import rdpcap                                      # Read Pcap
from scapy.utils import wrpcap                                      # Write Pcap

FrameLength = 1000
FrameLengthThroughput = 1498
FrameLengthLatency = 62
NumberFileCreate = 1          # There are 6 test cases
EthFrameCreate = [4,6,2]      # Each test case contains 4 Eth frames
EthPayLoadData = []
OptionalData = ["a1 ","b2 ","c3 ","d4 ","e5 ","f6 "]   # This data is optional
RawData = ["", "", "", "", "", ""]

''' Rule for ETH frame format'''
''' Single Channel Test Case'''
#PCL_06_0_001, PCL_06_0_002
DstMacAddr_01 = "20:11:74:90:50:01"
DstMacAddr_02_Wrong = "AA:BB:CC:DD:EE:FF"
DstMacAddr_02_Right = "20:11:74:90:50:01"

#PCL_06_0_003, PCL_06_0_004
DstMacAddr_03 = "20:11:74:90:50:10"
DstMacAddr_04_Wrong = "AA:BB:CC:DD:EE:FF"
DstMacAddr_04_Right = "20:11:74:90:50:10"

#PCL_06_0_005, PCL_06_0_006
DstMacAddr_05_Wrong = "AA:BB:CC:DD:EE:FF"
DstMacAddr_05_Right = "21:11:74:90:50:10"
DstMacAddr_06 = "21:11:74:90:50:10"

#PCL_06_0_014, PCL_06_0_015, PCL_06_0_017
DstMacAddr_14_01 = "20:11:74:90:50:01"
DstMacAddr_14_10 = "20:11:74:90:50:10"
DstIpAddr_14_01  = "192.169.0.1"
DstIpAddr_14_10  = "192.168.1.37"
DstMacAddr_15    = "20:11:74:90:50:10"
DstMacAddr_17_01 = "20:11:74:90:50:01"
DstMacAddr_17_10 = "20:11:74:90:50:10"
DstIpAddr_17_01  = "192.169.0.1"
DstIpAddr_17_10  = "192.168.1.69"

''' Multi Channel Test Case '''
#PCL_06_0_007, PCL_06_0_008
DstMacAddr_07 = "41:22:74:90:50:20"
DstMacAddr_08 = "41:22:74:90:50:21"

#PCL_06_0_011, PCL_06_0_012, PCL_06_0_013
DstMacAddr_12_01_0 = "41:22:74:90:50:22"
DstMacAddr_11_01_1 = "41:22:74:90:50:23"
DstMacAddr_13_0_1  = "41:22:74:90:50:24"
DstMacAddr_13_1_0  = "41:22:74:90:50:24"


#ETH Frame variable
SrcMacAddr  = "10:20:30:40:50:60" #Source MAC address is fixed
DstMacAddr  = "AA:BB:CC:DD:EE:FF"
DstIpAddr   = "192.168.1.1"
SrcIpAddr   = "192.168.1.100"
UdpDstPort  = 8225
UdpSrcPort  = 8080
VlanID = [72,15]
EthPayLoadLength = FrameLength - 12 - 20 - 8 # 12 byte MAC, 20 byte Ipv4 Header, 8 byte UDP header
EthPayLoadLengthThroughput = FrameLengthThroughput - 12 - 20 - 8
EthPayLoadLengthLatency = FrameLengthLatency - 12 - 20 - 8

TC_PCL_06_0_001 = False
TC_PCL_06_0_002 = False
TC_PCL_06_0_003 = False
TC_PCL_06_0_004 = False
TC_PCL_06_0_005 = False
TC_PCL_06_0_006 = False
TC_PCL_06_0_007 = False
TC_PCL_06_0_008 = False
TC_PCL_06_0_011 = False
TC_PCL_06_0_012 = False
TC_PCL_06_0_013 = False
TC_PCL_06_0_014 = True
TC_PCL_06_0_015 = False
TC_PCL_06_0_017 = False

class CreateData():
    def create_PCAP(self, index):  
        if (TC_PCL_06_0_001):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLength*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_01)/IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_001_Tx.pcap", [self.EthPacket],append=True)
        
        elif (TC_PCL_06_0_002):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLength*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                if ((frameIndex==0)or (frameIndex==1)):
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_02_Right) /IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                else:
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_02_Wrong) /IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_002_Tx.pcap", [self.EthPacket],append=True)
        
        elif (TC_PCL_06_0_003):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLength*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_03) /IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_003_Tx.pcap", [self.EthPacket],append=True)
        
        elif (TC_PCL_06_0_004):
            for frameIndex in range (EthFrameCreate[1]):
                EthPayLoadData.append(EthPayLoadLength*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                if ((frameIndex==0)or (frameIndex==1)):
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_04_Right) /IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                else:
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_04_Wrong) /IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_004_Tx.pcap", [self.EthPacket],append=True)
        
        elif (TC_PCL_06_0_005):
            for frameIndex in range (EthFrameCreate[1]):
                EthPayLoadData.append(EthPayLoadLength*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                if ((frameIndex==0)or (frameIndex==1)):
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_05_Right)/Dot1Q(vlan=72) /IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                else:
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_05_Wrong)/Dot1Q(vlan=15) /IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_005_Tx.pcap", [self.EthPacket],append=True)
        
        elif (TC_PCL_06_0_006):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLength*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_06) /Dot1Q(vlan=72)/ IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_006_Tx.pcap", [self.EthPacket],append=True)
        
        elif (TC_PCL_06_0_007):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLength*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                if ((frameIndex==0) or (frameIndex==1)): #Hai frame đầu tiên có DstMACAddr khớp với MAC table
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_07) /Dot1Q(vlan=0)/ IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                else: #Hai frame cuối có VLAN ID khớp với VLAN table
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr) /Dot1Q(vlan=72)/ IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_007_Tx.pcap", [self.EthPacket],append=True)
        
        elif (TC_PCL_06_0_008):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLength*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                if ((frameIndex==0) or (frameIndex==1)): #Hai frame đầu tiên có DstMACAddr khớp với MAC table
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_08) /Dot1Q(vlan=0)/ IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                else: #Hai frame cuối có VLAN ID khớp với VLAN table
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr) /Dot1Q(vlan=72)/ IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_008_Tx.pcap", [self.EthPacket],append=True)

        elif (TC_PCL_06_0_011):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLength*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                # Ethernet frame for port 0
                if ((frameIndex==0) or (frameIndex==1)):
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_11_01_1) /Dot1Q(vlan=0)/ IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                else:
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr) /Dot1Q(vlan=72)/ IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_011_Tx_port0.pcap", [self.EthPacket],append=True)
                
                # Ethernet frame for port 1
                if ((frameIndex==0) or (frameIndex==1)):
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_11_01_1) /Dot1Q(vlan=0)/ IP(dst= "192.168.1.80", src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                else:
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr) /Dot1Q(vlan=72)/ IP(dst= "192.168.1.80", src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_011_Tx_port1.pcap", [self.EthPacket],append=True)       
        elif (TC_PCL_06_0_012):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLength*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                # Ethernet frame for port 0
                if ((frameIndex==0) or (frameIndex==1)):
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_12_01_0) /Dot1Q(vlan=0)/ IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                else:
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr) /Dot1Q(vlan=72)/ IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_012_Tx_port0.pcap", [self.EthPacket],append=True)
                
                # Ethernet frame for port 1
                if ((frameIndex==0) or (frameIndex==1)):
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_12_01_0) /Dot1Q(vlan=0)/ IP(dst= "192.168.1.60", src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                else:
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr) /Dot1Q(vlan=72)/ IP(dst= "192.168.1.60", src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_012_Tx_port1.pcap", [self.EthPacket],append=True)
        
        elif (TC_PCL_06_0_013):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLength*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                # Ethernet frame for port 0
                if ((frameIndex==0) or (frameIndex==1)):
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_13_0_1) /Dot1Q(vlan=0)/ IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                else:
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr) /Dot1Q(vlan=72)/ IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_013_Tx_port0.pcap", [self.EthPacket],append=True)
                
                # Ethernet frame for port 1
                if ((frameIndex==0) or (frameIndex==1)):
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_13_1_0) /Dot1Q(vlan=0)/ IP(dst= "192.168.1.37", src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                else:
                    self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr) /Dot1Q(vlan=72)/ IP(dst= "192.168.1.37", src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_013_Tx_port1.pcap", [self.EthPacket],append=True)
        
        elif (TC_PCL_06_0_014):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLengthThroughput*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_14_01) /IP(dst= DstIpAddr_14_01, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_014_01.pcap", [self.EthPacket],append=True)
                
                self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_14_10) /IP(dst= DstIpAddr_14_10, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_014_10.pcap", [self.EthPacket],append=True)
        
        elif (TC_PCL_06_0_015):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLengthLatency*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                self.EthPacket = Ether(src= SrcMacAddr, dst = "74:90:50:00:00:04") /IP(dst= DstIpAddr, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_015_Tx.pcap", [self.EthPacket],append=True)
        elif (TC_PCL_06_0_017):
            for frameIndex in range (EthFrameCreate[0]):
                EthPayLoadData.append(EthPayLoadLengthThroughput*OptionalData[frameIndex])
                RawData[frameIndex] = bytearray.fromhex(EthPayLoadData[frameIndex])
                self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_17_01) /Dot1Q(vlan=72)/IP(dst= DstIpAddr_17_01, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_017_01.pcap", [self.EthPacket],append=True)
                
                self.EthPacket = Ether(src= SrcMacAddr, dst = DstMacAddr_17_10) /Dot1Q(vlan=103)/IP(dst= DstIpAddr_17_10, src=SrcIpAddr) / UDP(dport = UdpDstPort, sport = UdpSrcPort)/RawData[frameIndex]
                hexdump(self.EthPacket)
                wrpcap("PCL_06_0_017_10.pcap", [self.EthPacket],append=True)

if __name__ == "__main__":
    for file in range (NumberFileCreate):
        obj = CreateData()
        obj.create_PCAP(file)


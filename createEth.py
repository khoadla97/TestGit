import scapy
from scapy.all import Ether, IP, UDP, TCP, Dot1Q, Dot3, IPv6        # Ethernet type, format
from scapy.all import hexdump                                       # Dump Ethernet frame create
from scapy.utils import rdpcap                                      # Read Pcap
from scapy.utils import wrpcap                                      # Write Pcap
import csv

# For Create all Test Case Data
# TestCaseList = ["PCL_06_0_001","PCL_06_0_002","PCL_06_0_003","PCL_06_0_004",\
#                 "PCL_06_0_005","PCL_06_0_006","PCL_06_0_007","PCL_06_0_008",\
#                 "PCL_06_0_009","PCL_06_0_010","PCL_06_0_011","PCL_06_0_012",]

TestCaseList = ["PCL_06_0_001"] # For Create Single Test Case Data

class EthFrameCreate():
    def __init__(self):
        self.EthFrameCreate = 4     # 4 Eth Frame in 1 Pcap file
        # Ethernet Layer 2
        self.FrameType = ""
        self.DstMacAddr = ""
        self.SrcMacAddr = ""
        self.VlanTag = ""
        self.VlanID  = ""
        # Ethernet Layer 3
        self.DstIpAddr  = ""        # L2 Routing actually don't care Eth Layer 3
        self.SrcIpAddr  = ""        # But L3 forwarding will you this field
        # Ethernet Layer 4 (UDP)
        self.UdpDstPort = 8225      # Fixed, add to csv if want to modify
        self.UdpSrcPort = 8080      # Fixed, add to csv if want to modify
        self.EthPayLoad = ["a1", "b2", "c3", "d4"]
        # Abnormal/Normal Test Case
        self.Abnormal = ""
        self.DstMacAddr_Abnormal = ""   # abnormal will have 4 frame, 2 frame match routing table
                                        # and 2 frame not match routing table (wrong mac address)

    def ReadConfig(self, TestCaseID):
        with open(r"EthRoutConfig.csv", "r") as csv_file:
            csvReader = csv.reader(csv_file)
            next(csvReader)     # Next Header
            for row in csvReader:
                if TestCaseID in row:
                    self.FrameType = row[1]
                    self.DstMacAddr = row[2]
                    self.SrcMacAddr = row[3]
                    self.VlanTag = True if "TRUE" in row[4].upper() else False
                    self.VlanID = row[5]
                    self.EthPayLoadLength = int(row[8])
                    if "RAWETH" not in self.FrameType.upper():
                        self.DstIpAddr = row[6]
                        self.SrcIpAddr = row[7]
                    self.Abnormal = True if "ABNORMAL" in row[9].upper() else False
                    if (self.Abnormal):
                        self.DstMacAddr = row[10]

    def debug(self):
        print( self.EthFrameCreate, self.FrameType, self.DstMacAddr, self.SrcMacAddr, self.VlanTag, self.VlanID ,\
             self.DstIpAddr , self.UdpDstPort, self.UdpSrcPort, self.EthPayLoad)

    def CreatePcap(self, TestCase):
        # Clear old pcap file
        wrpcap(TestCase + ".pcap", "")
        for i in range (self.EthFrameCreate):
            EthPayLoad = bytearray.fromhex(self.EthPayLoad[i]*self.EthPayLoadLength)
            if (self.Abnormal):
                # For Abnormal case
                # Frame even will have right mac addr
                # Frame odd will have wrong dest mac addr
                if (i%2 == 0):
                    DestMacAddress = self.DstMacAddr
                else:
                    DestMacAddress = self.DstMacAddr_Abnormal
            else:
                DestMacAddress = self.DstMacAddr
            if "RAWETH" not in self.FrameType.upper():
                # Create Ethernet Layer 2
                EthPacket = Ether(dst = DestMacAddress, src = self.SrcMacAddr)
                if self.VlanTag:
                    EthPacket /= Dot1Q(vlan = self.VlanID)
                # Add Ethernet Layer 3
                # IP for IPv4
                # IPv6 for IPv6 (Not support in this scripts yet)
                EthPacket /= IP(dst = self.DstIpAddr, src = self.SrcIpAddr)
                # Add UDP Header
                EthPacket /= UDP(dport = self.UdpDstPort, sport = self.UdpSrcPort)
            else:   # Raw Ethernet
                # Create Layer 2 with 802.3 format
                EthPacket = Dot3(dst = DestMacAddress, src = self.SrcMacAddr)
                if self.VlanTag:
                    EthPacket /= Dot1Q(vlan = self.VlanID)
                # Raw Eth dont have layer 3
            # Add PayLoad
            EthPacket /= EthPayLoad
            hexdump(EthPacket)
            wrpcap(TestCase + "_Tx.pcap", EthPacket, append = True)

            
    def reset(self):
        self.__init__()

if __name__ == "__main__":
    for i in range(len(TestCaseList)):    
        obj = EthFrameCreate()
        obj.ReadConfig(TestCaseList[i])
        #obj.debug()

        obj.CreatePcap(TestCaseList[i])
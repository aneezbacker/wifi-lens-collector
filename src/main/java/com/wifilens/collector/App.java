package com.wifilens.collector;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.util.*;

public class App {
    public static void main(String[] args) throws Exception {
        PcapHandle handle = null;
        try {
            InetAddress addr = InetAddress.getByName("192.168.0.103");
            PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);

            int snapLen = 65536;
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            int timeout = 1000;
            handle = nif.openLive(snapLen, mode, timeout);

            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            System.out.println("No. of devices:" + allDevs.size());

            Map<String, Set<IpAddr>> macVsIpAddrMap = new HashMap<>();

            Set<String> phoneAddr = new HashSet<>();


            for (int i = 0; i < 1000; i++) {
                try {
                    Packet packet = handle.getNextPacketEx();

                    // get mac address
                    EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
                    String macAddr = ethernetPacket.getHeader().getSrcAddr().toString();

                    // get destination IP
                    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                    IpAddr ipAddr = new IpAddr(ipV4Packet.getHeader().getSrcAddr().toString(),
                            ipV4Packet.getHeader().getDstAddr().toString());

                    Set<IpAddr> ipAddrSet = macVsIpAddrMap.get(macAddr);
                    if (ipAddrSet == null) {
                        ipAddrSet = new HashSet<>();
                        macVsIpAddrMap.put(macAddr, ipAddrSet);
                    }

                    ipAddrSet.add(ipAddr);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            for (String macAddr : macVsIpAddrMap.keySet()) {
                System.out.println("==> MacAddr:" + macAddr);
                Set<IpAddr> ipAddrList = macVsIpAddrMap.get(macAddr);
                ipAddrList.forEach(System.out::println);
                System.out.println();
                System.out.println();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (handle != null) handle.close();
        }
    }
}

class IpAddr {
    private String srcIp;
    private String destIp;

    public IpAddr(String srcIp, String destIp) {
        this.srcIp = srcIp;
        this.destIp = destIp;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public String getDestIp() {
        return destIp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        IpAddr ipAddr = (IpAddr) o;

        if (!srcIp.equals(ipAddr.srcIp)) return false;
        return destIp.equals(ipAddr.destIp);
    }

    @Override
    public int hashCode() {
        int result = srcIp.hashCode();
        result = 31 * result + destIp.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "IpAddr{" +
                "srcIp='" + srcIp + '\'' +
                ", destIp='" + destIp + '\'' +
                '}';
    }
}
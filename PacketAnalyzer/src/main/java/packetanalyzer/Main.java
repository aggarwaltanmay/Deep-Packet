package packetanalyzer;

import packetanalyzer.models.EtherType;
import packetanalyzer.models.ParsedPacket;
import packetanalyzer.models.RawPacket;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class Main {

    private static void printPacketSummary(ParsedPacket pkt, int packetNum) {
        // Format timestamp
        Date date = new Date(pkt.timestampSec * 1000L);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC")); // match typical default behavior or local timezone, local is standard, but C++ used localtime
        sdf.setTimeZone(TimeZone.getDefault()); 
        
        System.out.println("\n========== Packet #" + packetNum + " ==========");
        System.out.printf("Time: %s.%06d\n", sdf.format(date), pkt.timestampUsec);

        // Ethernet layer
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.srcMac);
        System.out.println("  Destination MAC: " + pkt.destMac);
        System.out.printf("  EtherType:       0x%04x", pkt.etherType);

        if (pkt.etherType == EtherType.IPv4) {
            System.out.print(" (IPv4)");
        } else if (pkt.etherType == EtherType.IPv6) {
            System.out.print(" (IPv6)");
        } else if (pkt.etherType == EtherType.ARP) {
            System.out.print(" (ARP)");
        }
        System.out.println();

        // IP layer
        if (pkt.hasIp) {
            System.out.println("\n[IPv" + pkt.ipVersion + "]");
            System.out.println("  Source IP:      " + pkt.srcIp);
            System.out.println("  Destination IP: " + pkt.destIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.protocol));
            System.out.println("  TTL:            " + pkt.ttl);
        }

        // TCP layer
        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
            System.out.println("  Sequence Number:  " + pkt.seqNumber);
            System.out.println("  Ack Number:       " + pkt.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }

        // UDP layer
        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
        }

        // Payload info
        if (pkt.payloadLength > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.payloadLength + " bytes");

            // Print first 32 bytes of payload as hex
            System.out.print("  Preview: ");
            int previewLen = Math.min(pkt.payloadLength, 32);
            for (int i = 0; i < previewLen; i++) {
                System.out.printf("%02x ", pkt.payloadData[i] & 0xFF);
            }
            if (pkt.payloadLength > 32) {
                System.out.print("...");
            }
            System.out.println();
        }
    }

    private static void printUsage(String programName) {
        System.out.println("Usage: java -jar " + programName + " <pcap_file> [max_packets]");
        System.out.println("\nArguments:");
        System.out.println("  pcap_file   - Path to a .pcap file captured by Wireshark");
        System.out.println("  max_packets - (Optional) Maximum number of packets to display");
        System.out.println("\nExample:");
        System.out.println("  java -jar " + programName + " capture.pcap");
        System.out.println("  java -jar " + programName + " capture.pcap 10");
    }

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0 (Java)");
        System.out.println("====================================\n");

        if (args.length < 1) {
            printUsage("packet-analyzer.jar");
            System.exit(1);
        }

        String filename = args[0];
        int maxPackets = -1; // -1 means no limit

        if (args.length >= 2) {
            try {
                maxPackets = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid max_packets value: " + args[1]);
                System.exit(1);
            }
        }

        PcapReader reader = new PcapReader();
        if (!reader.open(filename)) {
            System.exit(1);
        }

        System.out.println("\n--- Reading packets ---");

        RawPacket rawPacket = new RawPacket();
        ParsedPacket parsedPacket = new ParsedPacket();
        int packetCount = 0;
        int parseErrors = 0;

        while (reader.readNextPacket(rawPacket)) {
            packetCount++;

            if (PacketParser.parse(rawPacket, parsedPacket)) {
                printPacketSummary(parsedPacket, packetCount);
            } else {
                System.err.println("Warning: Failed to parse packet #" + packetCount);
                parseErrors++;
            }

            if (maxPackets > 0 && packetCount >= maxPackets) {
                System.out.println("\n(Stopped after " + maxPackets + " packets)");
                break;
            }
        }

        System.out.println("\n====================================");
        System.out.println("Summary:");
        System.out.println("  Total packets read:  " + packetCount);
        System.out.println("  Parse errors:        " + parseErrors);
        System.out.println("====================================");

        reader.close();
    }
}

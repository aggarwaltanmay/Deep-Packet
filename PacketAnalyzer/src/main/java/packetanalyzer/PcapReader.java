package packetanalyzer;

import packetanalyzer.models.RawPacket;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class PcapReader {
    private static final int PCAP_MAGIC_NATIVE = 0xa1b2c3d4;
    private static final int PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

    private DataInputStream dis;
    private boolean needsByteSwap = false;
    private long snaplen = 0;

    public boolean open(String filename) {
        close();
        try {
            dis = new DataInputStream(new FileInputStream(filename));
            
            // Read Global Header (24 bytes)
            int magicNumber = dis.readInt();
            if (magicNumber == PCAP_MAGIC_NATIVE) {
                needsByteSwap = false;
            } else if (magicNumber == PCAP_MAGIC_SWAPPED) {
                needsByteSwap = true;
            } else {
                System.err.println("Error: Invalid PCAP magic number: 0x" + Integer.toHexString(magicNumber));
                close();
                return false;
            }

            short versionMajor = dis.readShort();
            short versionMinor = dis.readShort();
            int thiszone = dis.readInt();
            int sigfigs = dis.readInt();
            int rawSnaplen = dis.readInt();
            int network = dis.readInt();

            if (needsByteSwap) {
                versionMajor = Short.reverseBytes(versionMajor);
                versionMinor = Short.reverseBytes(versionMinor);
                thiszone = Integer.reverseBytes(thiszone);
                sigfigs = Integer.reverseBytes(sigfigs);
                rawSnaplen = Integer.reverseBytes(rawSnaplen);
                network = Integer.reverseBytes(network);
            }
            
            this.snaplen = Integer.toUnsignedLong(rawSnaplen);

            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + versionMajor + "." + versionMinor);
            System.out.println("  Snaplen: " + snaplen + " bytes");
            System.out.println("  Link type: " + network + (network == 1 ? " (Ethernet)" : ""));

            return true;
        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename);
            close();
            return false;
        }
    }

    public void close() {
        if (dis != null) {
            try {
                dis.close();
            } catch (IOException ignored) {}
            dis = null;
        }
        needsByteSwap = false;
    }

    public boolean readNextPacket(RawPacket packet) {
        if (dis == null) return false;

        try {
            // Read Packet Header (16 bytes)
            int tsSec = dis.readInt();
            int tsUsec = dis.readInt();
            int inclLen = dis.readInt();
            int origLen = dis.readInt();

            if (needsByteSwap) {
                tsSec = Integer.reverseBytes(tsSec);
                tsUsec = Integer.reverseBytes(tsUsec);
                inclLen = Integer.reverseBytes(inclLen);
                origLen = Integer.reverseBytes(origLen);
            }

            long uInclLen = Integer.toUnsignedLong(inclLen);
            
            if (uInclLen > snaplen || uInclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + uInclLen);
                return false;
            }

            byte[] data = new byte[(int) uInclLen];
            dis.readFully(data);

            packet.tsSec = Integer.toUnsignedLong(tsSec);
            packet.tsUsec = Integer.toUnsignedLong(tsUsec);
            packet.inclLen = uInclLen;
            packet.origLen = Integer.toUnsignedLong(origLen);
            packet.data = data;

            return true;
        } catch (IOException e) {
            // End of file or error
            return false;
        }
    }
}

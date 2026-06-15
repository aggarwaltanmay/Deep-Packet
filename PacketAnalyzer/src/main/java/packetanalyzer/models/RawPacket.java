package packetanalyzer.models;

public class RawPacket {
    public long tsSec;
    public long tsUsec;
    public long inclLen;
    public long origLen;
    public byte[] data;
}

package com.transficc.wiresharktools.pcap;

import org.agrona.MutableDirectBuffer;

//See: https://wiki.wireshark.org/Development/LibpcapFileFormat
class PcapFileHeader
{
    static final int ENCODED_LENGTH = 24;
    //See: http://www.tcpdump.org/linktypes.html
    private static final int ETHERNET_TYPE = 0x00000001;

    static void writePcapFileHeader(final MutableDirectBuffer buffer)
    {
        writeMagicNumber(buffer);
        writeLibPcapVersion(buffer);
        writeTimezoneOffset(buffer);
        writeTimestampAccuracy(buffer);
        writeSnapLength(buffer);
        writeLinkType(buffer);
    }


    private static void writeLinkType(final MutableDirectBuffer buffer)
    {
        buffer.putInt(20, ETHERNET_TYPE);
    }

    private static void writeSnapLength(final MutableDirectBuffer buffer)
    {
        buffer.putInt(16, 0x00040000);
    }

    private static void writeTimestampAccuracy(final MutableDirectBuffer buffer)
    {
        buffer.putInt(12, 0);
    }

    private static void writeTimezoneOffset(final MutableDirectBuffer buffer)
    {
        buffer.putInt(8, 0);
    }

    private static void writeLibPcapVersion(final MutableDirectBuffer buffer)
    {
        writeMajorVersion(buffer);
        writeMinorVersion(buffer);
    }

    private static void writeMinorVersion(final MutableDirectBuffer buffer)
    {
        buffer.putShort(6, (short)4);
    }

    private static void writeMajorVersion(final MutableDirectBuffer buffer)
    {
        buffer.putShort(4, (short)2);
    }

    private static void writeMagicNumber(final MutableDirectBuffer buffer)
    {
        buffer.putInt(0, 0xa1b2c3d4);
    }
}

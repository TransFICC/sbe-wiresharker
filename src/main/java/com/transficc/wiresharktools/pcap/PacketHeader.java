package com.transficc.wiresharktools.pcap;

import org.agrona.MutableDirectBuffer;

//See: https://wiki.wireshark.org/Development/LibpcapFileFormat
class PacketHeader
{
    static final int ENCODED_LENGTH = 16;

    static void writePacketHeader(final MutableDirectBuffer buffer, final int offset, final int packetLength)
    {
        timestampSeconds(buffer, offset);
        timestampMicroseconds(buffer, offset);
        inclLength(buffer, offset, packetLength);
        originalLength(buffer, offset, packetLength);
    }

    private static void originalLength(final MutableDirectBuffer buffer, final int offset, final int packetLength)
    {
        buffer.putInt(offset + 12, packetLength);
    }

    private static void inclLength(final MutableDirectBuffer buffer, final int offset, final int packetLength)
    {
        buffer.putInt(offset + 8, packetLength);
    }

    private static void timestampMicroseconds(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putInt(offset + 4, 0x00_0e_9c_76);
    }

    private static void timestampSeconds(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putInt(offset, 0x60_04_70_d3);
    }
}

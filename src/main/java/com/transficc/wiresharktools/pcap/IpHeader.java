package com.transficc.wiresharktools.pcap;

import java.nio.ByteOrder;

import org.agrona.MutableDirectBuffer;

//See: https://tools.ietf.org/html/rfc791#page-11
class IpHeader
{
    static final int ENCODED_LENGTH = 20;
    private static final int VERSION_4 = 4;
    private static final short IDENTITY = (short)0xd310;
    private static final int NO_FRAGMENTATION = 2;
    private static final byte TCP = (byte)6;

    static void writeIpHeader(final MutableDirectBuffer buffer, final int offset, final int totalLength)
    {
        version(buffer, offset);
        headerLength(buffer, offset);
        serviceType(buffer, offset);
        totalLength(buffer, offset, totalLength);
        identification(buffer, offset);
        flags(buffer, offset);
        fragmentOffset(buffer, offset);
        ttl(buffer, offset);
        protocol(buffer, offset);
        headerChecksum(buffer, offset);
        sourceAddress(buffer, offset);
        destinationAddress(buffer, offset);
        options(buffer, offset);
    }

    private static void version(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putByte(offset, (byte)(VERSION_4 << 4));
    }

    private static void headerLength(final MutableDirectBuffer buffer, final int offset)
    {
        final byte version = buffer.getByte(offset);
        buffer.putByte(offset, (byte)(version | 5));
    }

    private static void serviceType(final MutableDirectBuffer buffer, final int offset)
    {

        buffer.putByte(offset + 1, (byte)0);
    }

    private static void totalLength(final MutableDirectBuffer buffer, final int offset, final int totalLength)
    {
        buffer.putShort(offset + 2, (short)totalLength, ByteOrder.BIG_ENDIAN);
    }

    private static void identification(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putShort(offset + 4, IDENTITY, ByteOrder.BIG_ENDIAN);
    }

    private static void flags(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putShort(offset + 6, (short) (NO_FRAGMENTATION << 13), ByteOrder.BIG_ENDIAN);
    }

    private static void fragmentOffset(final MutableDirectBuffer buffer, final int offset)
    {
        final short noFragmentFlags = buffer.getShort(offset + 6, ByteOrder.BIG_ENDIAN);
        buffer.putShort(offset + 6, noFragmentFlags, ByteOrder.BIG_ENDIAN);
    }

    private static void ttl(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putByte(offset + 8, (byte)64);
    }

    private static void protocol(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putByte(offset + 9, TCP);
    }

    private static void headerChecksum(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putShort(offset + 10, (short)0, ByteOrder.BIG_ENDIAN);
    }

    private static void sourceAddress(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putByte(offset + 12, (byte)127);
        buffer.putByte(offset + 13, (byte)0);
        buffer.putByte(offset + 14, (byte)0);
        buffer.putByte(offset + 15, (byte)1);
    }

    private static void destinationAddress(final MutableDirectBuffer buffer, final int offset)
    {

        buffer.putByte(offset + 16, (byte)192);
        buffer.putByte(offset + 17, (byte)168);
        buffer.putByte(offset + 18, (byte)1);
        buffer.putByte(offset + 19, (byte)1);
    }

    private static void options(final MutableDirectBuffer buffer, final int offset)
    {
    }
}

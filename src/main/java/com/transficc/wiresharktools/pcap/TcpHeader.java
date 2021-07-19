package com.transficc.wiresharktools.pcap;

import java.nio.ByteOrder;

import org.agrona.MutableDirectBuffer;

//See: https://tools.ietf.org/html/rfc793#page-15
class TcpHeader
{
    static final int ENCODED_LENGTH = 32;

    private static final int PUSH = 8;
    private static final int ACK = 16;
    private static final int NO_OP_OPTION = 1;
    private static final int TIMESTAMP_OPTION = 8;
    private static final int TIMESTAMP_LENGTH = 10;
    private static final int BASE_SEQ = 0xa582dce1;

    static void writeTcpHeader(final MutableDirectBuffer buffer, final int offset, final int seqNum, final int srcPort, final int destPort)
    {
        sourcePort(buffer, offset, srcPort);
        destinationPort(buffer, offset, destPort);
        sequenceNumber(buffer, offset, seqNum);
        acknowledgementNumber(buffer, offset);
        headerLength(buffer, offset);
        flags(buffer, offset);
        windowSize(buffer, offset);
        checksum(buffer, offset);
        urgentPointer(buffer, offset);
        options(buffer, offset);
    }

    private static void sourcePort(final MutableDirectBuffer buffer, final int offset, final int srcPort)
    {
        buffer.putShort(offset, (short)srcPort, ByteOrder.BIG_ENDIAN);
    }

    private static void destinationPort(final MutableDirectBuffer buffer, final int offset, final int destPort)
    {
        buffer.putShort(offset + 2, (short)destPort, ByteOrder.BIG_ENDIAN);
    }

    private static void sequenceNumber(final MutableDirectBuffer buffer, final int offset, final int seqNum)
    {
        buffer.putInt(offset + 4, BASE_SEQ + seqNum, ByteOrder.BIG_ENDIAN);
    }

    private static void acknowledgementNumber(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putInt(offset + 8, 0x13f71e9b, ByteOrder.BIG_ENDIAN);
    }

    private static void headerLength(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putShort(offset + 12, (short)(8 << 12), ByteOrder.BIG_ENDIAN);
    }

    private static void flags(final MutableDirectBuffer buffer, final int offset)
    {
        final short original = buffer.getShort(offset + 12, ByteOrder.BIG_ENDIAN);
        buffer.putShort(offset + 12, (short)(original | PUSH | ACK), ByteOrder.BIG_ENDIAN);
    }

    private static void windowSize(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putShort(offset + 14, (short)512, ByteOrder.BIG_ENDIAN);
    }

    private static void checksum(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putShort(offset + 16, (short)0xfe4c, ByteOrder.BIG_ENDIAN);
    }

    private static void urgentPointer(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putShort(offset + 18, (short)0, ByteOrder.BIG_ENDIAN);
    }

    private static void options(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putByte(offset + 20, (byte)NO_OP_OPTION);
        buffer.putByte(offset + 21, (byte)NO_OP_OPTION);

        buffer.putByte(offset + 22, (byte)TIMESTAMP_OPTION);
        buffer.putByte(offset + 23, (byte)TIMESTAMP_LENGTH);
        buffer.putInt(offset + 24, (byte)0xd1_56_58_d7, ByteOrder.BIG_ENDIAN);
        buffer.putInt(offset + 28, (byte)0x24_fd_72_b3, ByteOrder.BIG_ENDIAN);
    }
}

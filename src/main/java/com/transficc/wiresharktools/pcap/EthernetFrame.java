package com.transficc.wiresharktools.pcap;

import java.nio.ByteOrder;

import org.agrona.MutableDirectBuffer;

//See: http://www.networksorcery.com/enp/protocol/IEEE8023.htm
class EthernetFrame
{
    static final int ENCODED_LENGTH = 14;
    private static final byte[] EMPTY_ADDRESS = {0, 0, 0, 0, 0, 0};
    //http://www.networksorcery.com/enp/protocol/802/ethertypes.htm
    private static final short IP_V4 = (short)0x0800;

    static void writeEthernetFrame(final MutableDirectBuffer buffer, final int offset)
    {
        destinationAddress(buffer, offset);
        sourceAddress(buffer, offset);
        type(buffer, offset);
    }

    private static void destinationAddress(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putBytes(offset, EMPTY_ADDRESS);
    }

    private static void sourceAddress(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putBytes(offset + 6, EMPTY_ADDRESS);
    }

    private static void type(final MutableDirectBuffer buffer, final int offset)
    {
        buffer.putShort(offset + 12, IP_V4, ByteOrder.BIG_ENDIAN);
    }
}

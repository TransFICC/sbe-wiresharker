package com.transficc.wiresharktools.pcap;

import org.agrona.MutableDirectBuffer;

public class PcapFile
{
    public static int writePcap(final MutableDirectBuffer buffer, final int srcPort, final int destPort, final byte[]... messages)
    {
        PcapFileHeader.writePcapFileHeader(buffer);
        int totalLength = PcapFileHeader.ENCODED_LENGTH;
        int seqNum = 0;
        for (int i = 0, messagesLength = messages.length; i < messagesLength; i++)
        {
            final byte[] message = messages[i];
            final int packetLength = message.length + EthernetFrame.ENCODED_LENGTH + IpHeader.ENCODED_LENGTH + TcpHeader.ENCODED_LENGTH;
            final int ipHeaderLength = message.length + IpHeader.ENCODED_LENGTH + TcpHeader.ENCODED_LENGTH;

            PacketHeader.writePacketHeader(buffer, totalLength, packetLength);
            EthernetFrame.writeEthernetFrame(buffer, totalLength + PacketHeader.ENCODED_LENGTH);
            IpHeader.writeIpHeader(buffer, totalLength + PacketHeader.ENCODED_LENGTH + EthernetFrame.ENCODED_LENGTH, ipHeaderLength);
            TcpHeader.writeTcpHeader(buffer, totalLength + PacketHeader.ENCODED_LENGTH + EthernetFrame.ENCODED_LENGTH + IpHeader.ENCODED_LENGTH, seqNum, srcPort, destPort);
            buffer.putBytes(totalLength + PacketHeader.ENCODED_LENGTH + EthernetFrame.ENCODED_LENGTH + IpHeader.ENCODED_LENGTH + TcpHeader.ENCODED_LENGTH, message);
            totalLength += PacketHeader.ENCODED_LENGTH + EthernetFrame.ENCODED_LENGTH + IpHeader.ENCODED_LENGTH + TcpHeader.ENCODED_LENGTH + message.length;
            seqNum += message.length;
        }

        return totalLength;
    }
}

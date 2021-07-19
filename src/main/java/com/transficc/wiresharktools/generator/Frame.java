package com.transficc.wiresharktools.generator;

import com.transficc.wiresharktools.generator.schemaparsing.SimpleType;

public final class Frame
{
    private final SimpleType messageLengthType;
    private final int offsetToMessageLength;
    private final boolean lengthIncludesFrame;
    private final int additionalDataInFrameLength;

    public Frame(final SimpleType messageLengthType, final int offsetToMessageLength, final int additionalDataInFrameLength, final boolean lengthIncludesFrame)
    {
        this.messageLengthType = messageLengthType;
        this.additionalDataInFrameLength = additionalDataInFrameLength;
        this.offsetToMessageLength = offsetToMessageLength;
        this.lengthIncludesFrame = lengthIncludesFrame;
    }

    public boolean lengthIncludesFrame()
    {
        return lengthIncludesFrame;
    }


    public SimpleType messageLengthType()
    {
        return messageLengthType;
    }

    public int offsetToMessageLength()
    {
        return offsetToMessageLength;
    }

    public int additionalDataInFrameLength()
    {
        return additionalDataInFrameLength;
    }
}

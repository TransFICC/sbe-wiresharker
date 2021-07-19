package com.transficc.wiresharktools.generator.schemaparsing;

public final class PrimitiveArray implements ComplexType
{
    private final SimpleType simpleType;
    private final int offset;
    private final int length;

    public PrimitiveArray(final SimpleType simpleType, final int offset, final int length)
    {
        this.simpleType = simpleType;
        this.offset = offset;
        this.length = length;
    }

    public int length()
    {
        return length;
    }

    public SimpleType simpleType()
    {
        return simpleType;
    }
}

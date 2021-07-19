package com.transficc.wiresharktools.generator.schemaparsing;

public final class CharacterArray implements ComplexType
{
    private final SimpleType type;
    private final int offset;
    private final int length;

    public CharacterArray(final SimpleType type, final int offset, final int length)
    {
        this.type = type;
        this.offset = offset;
        this.length = length;
    }

    public SimpleType simpleType()
    {
        return type;
    }

    public int length()
    {
        return length;
    }
}

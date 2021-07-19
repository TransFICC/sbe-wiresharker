package com.transficc.wiresharktools.generator.schemaparsing;

public enum SimpleType
{
    UINT8("uint8", Base.DEC.render(), 1),
    UINT16("uint16", Base.DEC.render(), 2),
    UINT32("uint32", Base.DEC.render(), 4),
    UINT64("uint64", Base.DEC.render(), 8),
    INT8("int8", Base.DEC.render(), 1),
    INT16("int16", Base.DEC.render(), 2),
    INT32("int32", Base.DEC.render(), 4),
    INT64("int64", Base.DEC.render(), 8),
    FLOAT("float", Base.DEC.render(), 4),
    DOUBLE("double", Base.DEC.render(), 8),
    STRING("string", Base.ASCII.render(), 1),
    NONE("none", Base.DEC.render(), 0);

    private final String fieldType;
    private final String base;
    private final int lengthInBytes;

    SimpleType(final String fieldType, final String base, final int lengthInBytes)
    {
        this.fieldType = fieldType;
        this.base = base;
        this.lengthInBytes = lengthInBytes;
    }

    public String base()
    {
        return base;
    }

    public String fieldType()
    {
        return fieldType;
    }

    public int lengthInBytes()
    {
        return lengthInBytes;
    }
}

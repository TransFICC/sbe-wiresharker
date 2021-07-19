package com.transficc.wiresharktools.generator.schemaparsing;

public final class VariableLengthData implements ComplexType
{
    private final SimpleType lengthType;
    private final Base dataEncodingType;

    public VariableLengthData(final SimpleType lengthType, final Base dataEncodingType)
    {
        this.lengthType = lengthType;
        this.dataEncodingType = dataEncodingType;
    }

    public SimpleType lengthType()
    {
        return lengthType;
    }

    public Base dataEncodingType()
    {
        return dataEncodingType;
    }
}

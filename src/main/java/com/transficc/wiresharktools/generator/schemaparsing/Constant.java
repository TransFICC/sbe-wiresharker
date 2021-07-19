package com.transficc.wiresharktools.generator.schemaparsing;

public final class Constant implements ComplexType
{
    private final SimpleType simpleType;
    private final String value;

    public Constant(final SimpleType simpleType, final String value)
    {
        this.simpleType = simpleType;
        this.value = value;
    }

    public SimpleType simpleType()
    {
        return simpleType;
    }

    public String value()
    {
        return value;
    }
}

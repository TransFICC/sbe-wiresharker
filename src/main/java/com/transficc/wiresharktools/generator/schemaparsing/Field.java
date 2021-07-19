package com.transficc.wiresharktools.generator.schemaparsing;

public final class Field
{
    private final SimpleType type;
    private final String name;
    private final int offset;
    private final String fullyQualifiedName;
    private final ComplexType complexType;

    public SimpleType simpleType()
    {
        if (type == SimpleType.NONE)
        {
            throw new IllegalStateException("Should not be accessing simple type when not set for: " + name);
        }
        return type;
    }

    public String name()
    {
        return name;
    }

    public int offset()
    {
        return offset;
    }

    public ComplexType complexType()
    {
        if (complexType == null)
        {
            throw new IllegalStateException("Should not be accessing complex type when not set for: " + name);
        }
        return complexType;
    }

    public boolean isSimpleType()
    {
        return complexType == null;
    }

    public Field(final SimpleType type, final String name, final int offset, final String fullyQualifiedName)
    {
        this.type = type;
        this.name = name;
        this.offset = offset;
        this.fullyQualifiedName = fullyQualifiedName;
        this.complexType = null;
    }

    public String fullyQualifiedName()
    {
        return fullyQualifiedName;
    }

    public Field(final ComplexType complexType, final String name, final int offset, final String fullyQualifiedName)
    {
        this.type = SimpleType.NONE;
        this.name = name;
        this.offset = offset;
        this.complexType = complexType;
        this.fullyQualifiedName = fullyQualifiedName;
    }
}

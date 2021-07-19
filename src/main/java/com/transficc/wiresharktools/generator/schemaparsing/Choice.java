package com.transficc.wiresharktools.generator.schemaparsing;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public final class Choice implements ComplexType
{
    private final SimpleType simpleType;
    private final String name;
    private final int offset;
    private final Map<Long, String> mapping = new HashMap<>();

    public Choice(final SimpleType simpleType, final String name, final int offset)
    {
        this.simpleType = simpleType;
        this.name = name;
        this.offset = offset;
    }

    public Map<Long, String> mapping()
    {
        return Collections.unmodifiableMap(mapping);
    }

    public SimpleType simpleType()
    {
        return simpleType;
    }

    public String name()
    {
        return name;
    }

    public void addMapping(final long bitPosition, final String value)
    {
        mapping.put(bitPosition, value);
    }
}

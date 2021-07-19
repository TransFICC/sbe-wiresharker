package com.transficc.wiresharktools.generator.schemaparsing;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public final class ConstantEnumeration implements ComplexType
{
    private final Map<Long, String> mapping = new HashMap<>();
    private final SimpleType simpleType;
    private final String constantValue;
    private final long constantKey;

    public ConstantEnumeration(final SimpleType simpleType, final String constantValue, final long constantKey)
    {
        this.simpleType = simpleType;
        this.constantValue = constantValue;
        this.constantKey = constantKey;
    }

    public String value()
    {
        return constantValue;
    }

    public long key()
    {
        return constantKey;
    }

    public SimpleType simpleType()
    {
        return simpleType;
    }

    public void addMapping(final long key, final String value)
    {
        mapping.put(key, value);
    }

    public Map<Long, String> mapping()
    {
        return Collections.unmodifiableMap(mapping);
    }
}

package com.transficc.wiresharktools.generator.schemaparsing;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Enumeration implements ComplexType
{
    private final SimpleType type;
    private final int offset;
    private final Map<Long, String> mapping = new HashMap<>();

    public Enumeration(final SimpleType encodedType, final int offset)
    {
        this.type = encodedType;
        this.offset = offset;
    }

    public SimpleType simpleType()
    {
        return type;
    }

    public Map<Long, String> mapping()
    {
        return Collections.unmodifiableMap(mapping);
    }

    public void addMapping(final long key, final String value)
    {
        mapping.put(key, value);
    }
}

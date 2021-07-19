package com.transficc.wiresharktools.generator.schemaparsing;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class Composite implements FieldBundle, ComplexType
{
    private final List<Field> fields = new ArrayList<>();
    private final int encodedLength;

    public Composite(final int encodedLength)
    {
        this.encodedLength = encodedLength;
    }

    @Override
    public void addField(final Field field)
    {
        fields.add(field);
    }

    @Override
    public List<Field> fields()
    {
        return Collections.unmodifiableList(fields);
    }

    public int encodedLength()
    {
        return encodedLength;
    }
}

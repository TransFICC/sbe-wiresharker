package com.transficc.wiresharktools.generator.schemaparsing;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class Group implements FieldBundle, ComplexType
{
    private final List<Field> fields = new ArrayList<>();
    private final SimpleType numInGroup;
    private final int offsetBeforeBlockLength;
    private final SimpleType blockLength;
    private final int offsetBeforeNumInGroup;
    private final int headerLength;

    public Group(
            final int offsetBeforeBlockLength,
            final SimpleType blockLength,
            final int offsetBeforeNumInGroup,
            final SimpleType numInGroup,
            final int headerLength
    )
    {
        this.offsetBeforeBlockLength = offsetBeforeBlockLength;
        this.blockLength = blockLength;
        this.offsetBeforeNumInGroup = offsetBeforeNumInGroup;
        this.numInGroup = numInGroup;
        this.headerLength = headerLength;
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

    public SimpleType numInGroup()
    {
        return numInGroup;
    }

    public int offsetBeforeNumInGroup()
    {
        return offsetBeforeNumInGroup;
    }

    public int offsetBeforeBlockLength()
    {
        return offsetBeforeBlockLength;
    }

    public SimpleType blockLength()
    {
        return blockLength;
    }

    public int headerLength()
    {
        return headerLength;
    }
}

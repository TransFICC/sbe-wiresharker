package com.transficc.wiresharktools.generator.schemaparsing;

import java.util.List;

public interface FieldBundle
{
    void addField(final Field field);

    List<Field> fields();
}

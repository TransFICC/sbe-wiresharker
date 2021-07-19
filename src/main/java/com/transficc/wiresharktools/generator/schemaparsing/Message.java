package com.transficc.wiresharktools.generator.schemaparsing;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class Message implements FieldBundle
{
    private final List<Field> fields = new ArrayList<>();
    private final int templateId;
    private final String name;

    public Message(final int templateId, final String name)
    {
        this.templateId = templateId;
        this.name = name;
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

    public String name()
    {
        return name;
    }

    public int id()
    {
        return templateId;
    }
}

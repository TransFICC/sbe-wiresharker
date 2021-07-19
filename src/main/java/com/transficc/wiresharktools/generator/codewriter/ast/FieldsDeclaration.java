package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.ArrayList;
import java.util.List;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class FieldsDeclaration implements Renderable
{
    private final List<String> fieldNames = new ArrayList<>();
    private final String protocolTree;

    public FieldsDeclaration(final String protocolTree)
    {
        this.protocolTree = protocolTree;
    }

    public void add(final String fieldName)
    {
        fieldNames.add(fieldName);
    }

    @Override
    public String render(final Indentation indentation)
    {
        return protocolTree + ".fields = { " + String.join(", ", fieldNames) + " }";
    }
}

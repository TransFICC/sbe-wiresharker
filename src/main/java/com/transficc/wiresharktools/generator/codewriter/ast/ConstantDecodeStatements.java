package com.transficc.wiresharktools.generator.codewriter.ast;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public class ConstantDecodeStatements implements DecodeStatements
{
    private final String protoTypeName;
    private final String subTree;
    private final String value;

    public ConstantDecodeStatements(final String protoTypeName, final String subTree, final String value)
    {
        this.protoTypeName = protoTypeName;
        this.subTree = subTree;
        this.value = value;
    }

    @Override
    public String render(final Indentation indentation)
    {
        return indentation + "local " + protoTypeName + " = " + subTree + ":add_le(" + protoTypeName + ", " + value + ")";
    }

    @Override
    public boolean isFixedLength()
    {
        return true;
    }
}

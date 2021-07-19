package com.transficc.wiresharktools.generator.codewriter.ast;

import com.transficc.wiresharktools.generator.codewriter.Indentation;


import static com.transficc.wiresharktools.generator.codewriter.CodeWriter.INITIAL_OFFSET_VAR;

public final class BasicDecodeStatements implements DecodeStatements
{
    private final String protoTypeName;
    private final String subTree;
    private final int encodedLength;
    private final int offset;

    public BasicDecodeStatements(final String protoTypeName, final String subTree, final int encodedLength, final int offset)
    {
        this.protoTypeName = protoTypeName;
        this.subTree = subTree;
        this.encodedLength = encodedLength;
        this.offset = offset;
    }

    @Override
    public String render(final Indentation indentation)
    {
        final String offsetExpression;
        if (offset == 0)
        {
            offsetExpression = "offset";
        }
        else
        {
            offsetExpression = "offsetToStartOfBlock + " + offset;
        }
        return indentation + subTree + ":add_le(" + protoTypeName + ", buffer(" + offsetExpression + ", " + encodedLength + "))" + "\n" +
               indentation + "offset = " + offsetExpression + " + " + encodedLength;
    }

    @Override
    public boolean isFixedLength()
    {
        return true;
    }
}

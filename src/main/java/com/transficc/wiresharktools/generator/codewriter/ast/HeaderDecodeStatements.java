package com.transficc.wiresharktools.generator.codewriter.ast;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class HeaderDecodeStatements implements Renderable
{
    private final String protoTypeName;
    private final int encodedLength;

    public HeaderDecodeStatements(final String protoTypeName, final int encodedLength)
    {
        this.protoTypeName = protoTypeName;
        this.encodedLength = encodedLength;
    }

    @Override
    public String render(final Indentation indentation)
    {
        return indentation + "subtree:add_le(" + protoTypeName + ", buffer(offset, " + encodedLength + "))\n" +
               indentation + "offset = offset + " + encodedLength;
    }
}

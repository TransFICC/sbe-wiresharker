package com.transficc.wiresharktools.generator.codewriter.ast;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public class VarLengthDecodeStatements implements DecodeStatements
{
    private final String protoTypeName;
    private final String subTree;
    private final int lengthFieldSize;

    public VarLengthDecodeStatements(final String protoTypeName, final String subTree, final int lengthFieldSize)
    {
        this.protoTypeName = protoTypeName;
        this.subTree = subTree;
        this.lengthFieldSize = lengthFieldSize;
    }

    @Override
    public String render(final Indentation indentation)
    {
        final String varLengthName = "varLength_" + protoTypeName;
        return indentation + "local " + varLengthName + " = buffer(offset, " + lengthFieldSize + "):le_uint" + (lengthFieldSize > 4 ? "64" : "") + "()" + "\n" +
               indentation + "offset = offset + " + lengthFieldSize + "\n" +
               indentation + subTree + ":add_le(" + protoTypeName + ", buffer(offset, " + varLengthName + "))" + "\n" +
               indentation + "offset = offset + " + varLengthName;
    }

    @Override
    public boolean isFixedLength()
    {
        return false;
    }
}

package com.transficc.wiresharktools.generator.codewriter.ast;

import com.transficc.wiresharktools.generator.codewriter.Indentation;


import static com.transficc.wiresharktools.generator.codewriter.CodeWriter.INITIAL_OFFSET_VAR;

public final class ArrayDecodeStatements implements DecodeStatements
{
    private final String protoTypeName;
    private final String subTree;
    private final String fieldName;
    private final int encodedLength;
    private final int offset;
    private final int length;

    public ArrayDecodeStatements(final String protoTypeName, final String subTree, final String fieldName, final int encodedLength, final int offset, final int length)
    {
        this.protoTypeName = protoTypeName;
        this.subTree = subTree;
        this.fieldName = fieldName;
        this.encodedLength = encodedLength;
        this.offset = offset;
        this.length = length;
    }

    @Override
    public String render(final Indentation indentation)
    {
        String retVal;
        if (offset != 0)
        {
            retVal = indentation + "offset = offsetToStartOfBlock + " + offset;
        }
        else
        {
            retVal = "";
        }

        for (int i = 0; i < length; i++)
        {
            final String thisNode = protoTypeName + "Node";
            retVal += indentation + "local " + thisNode + " = " + subTree + ":add_le(" + protoTypeName + ", buffer(offset, " + encodedLength + "))" + "\n" +
                      indentation + thisNode + ":set_text(\"" + fieldName + "[" + i + "]\")" + "\n" +
                      indentation + "offset = offset + " + encodedLength;
        }
        return retVal;
    }

    @Override
    public boolean isFixedLength()
    {
        return true;
    }
}

package com.transficc.wiresharktools.generator.codewriter.ast;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class BitFieldProtoType implements ProtoType
{
    private final String protoTypeName;
    private final String sbeFieldName;
    private final String encoding;
    private final String setValue;
    private final String unsetValue;
    private final String fieldType;
    private final int position;

    public BitFieldProtoType(
            final String protoTypeName,
            final String sbeFieldName,
            final String encoding,
            final String setValue,
            final String unsetValue,
            final String fieldType,
            final int position
    )
    {
        this.protoTypeName = protoTypeName;
        this.sbeFieldName = sbeFieldName;
        this.encoding = encoding;
        this.setValue = setValue;
        this.unsetValue = unsetValue;
        this.fieldType = fieldType;
        this.position = position;
    }

    @Override
    public String render(final Indentation indentation)
    {
        final String mask = mask(position);
        return protoTypeName +
               " = ProtoField." +
               fieldType +
               "(\"" +
               sbeFieldName +
               "\", \"" +
               sbeFieldName +
               "\", " +
               encoding +
               ", {[0]=\"" +
               unsetValue +
               "\", [1]=\"" +
               setValue +
               "\"}, " +
               mask +
               ")";

    }

    private static String mask(final int position)
    {
        return "0x" + Long.toHexString(1L << (position));
    }
}

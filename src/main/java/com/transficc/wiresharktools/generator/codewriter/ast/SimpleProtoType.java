package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.Optional;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class SimpleProtoType implements ProtoType
{
    private final String protoTypeName;
    private final String sbeFieldName;
    private final String fieldType;
    private final String base;

    public SimpleProtoType(final String protoTypeName, final String sbeFieldName, final String fieldType, final String base)
    {
        this.protoTypeName = protoTypeName;
        this.sbeFieldName = sbeFieldName;
        this.fieldType = fieldType;
        this.base = base;
    }

    @Override
    public String render(final Indentation indentation)
    {
        return AstUtils.protoTypeDeclaration(protoTypeName, fieldType, sbeFieldName, Optional.ofNullable(base));
    }
}

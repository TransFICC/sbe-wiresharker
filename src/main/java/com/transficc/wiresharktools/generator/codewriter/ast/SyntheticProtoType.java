package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.Optional;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class SyntheticProtoType implements ProtoType
{
    private final String protoTypeName;
    private final String sbeFieldName;

    public SyntheticProtoType(final String protoTypeName, final String sbeFieldName)
    {
        this.protoTypeName = protoTypeName;
        this.sbeFieldName = sbeFieldName;
    }

    @Override
    public String render(final Indentation indentation)
    {
        return AstUtils.protoTypeDeclaration(protoTypeName, "none", sbeFieldName, Optional.empty());
    }
}

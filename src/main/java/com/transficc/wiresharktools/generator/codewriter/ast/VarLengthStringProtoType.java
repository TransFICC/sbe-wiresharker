package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.Optional;

import com.transficc.wiresharktools.generator.codewriter.Indentation;
import com.transficc.wiresharktools.generator.schemaparsing.SimpleType;

public final class VarLengthStringProtoType implements ProtoType
{
    private final String protoTypeName;
    private final String sbeFieldName;
    private final String encoding;

    public VarLengthStringProtoType(final String protoTypeName, final String sbeFieldName, final String encoding)
    {
        this.protoTypeName = protoTypeName;
        this.sbeFieldName = sbeFieldName;
        this.encoding = encoding;
    }

    @Override
    public String render(final Indentation indentation)
    {
        return AstUtils.protoTypeDeclaration(protoTypeName, SimpleType.STRING.fieldType(), sbeFieldName, Optional.ofNullable(encoding));
    }

}

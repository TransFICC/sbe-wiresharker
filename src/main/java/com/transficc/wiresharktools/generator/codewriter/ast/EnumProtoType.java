package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


import com.transficc.wiresharktools.generator.codewriter.Indentation;


import static com.transficc.wiresharktools.generator.GenUtils.camelCase;

public final class EnumProtoType implements ProtoType
{
    private final String fieldName;
    private final String protoTypeName;
    private final String enumName;
    private final Set<String> enumsMapped;
    private final Map<Long, String> mapping;
    private final String schema;
    private final String fieldType;
    private final String base;

    public EnumProtoType(
            final String sbeFieldName,
            final String protoTypeName,
            final String enumName,
            final Set<String> enumsMapped,
            final Map<Long, String> mapping,
            final String schema,
            final String fieldType,
            final String base
    )
    {
        this.fieldName = sbeFieldName;
        this.protoTypeName = protoTypeName;
        this.enumName = enumName;
        this.enumsMapped = enumsMapped;
        this.mapping = mapping;
        this.schema = schema;
        this.fieldType = fieldType;
        this.base = base;
    }

    @Override
    public String render(final Indentation indentation)
    {
        final String enumTableName = camelCase(schema) + "_" + enumName;
        final String tableDefinition;
        if (enumsMapped.contains(enumTableName))
        {
            tableDefinition = "";
        }
        else
        {
            tableDefinition = enumTable(mapping, enumTableName) + "\n";
            enumsMapped.add(enumTableName);
        }
        return tableDefinition + protoTypeName +
               " = ProtoField." +
               fieldType +
               "(\"" +
               fieldName +
               "\", \"" +
               fieldName +
               "\", " +
               base +
               ", " +
               enumTableName +
               ")";

    }

    private static String enumTable(final Map<Long, String> mapping, final String enumTableName)
    {
        final String table;
        table = enumTableName + " = {\n" +
                mapping
                        .entrySet()
                        .stream()
                        .map(validValue -> "    [" + validValue.getKey() + "] = \"" + validValue.getValue() + "\"")
                        .collect(Collectors.joining(",\n")) +
                "\n}";
        return table;
    }
}

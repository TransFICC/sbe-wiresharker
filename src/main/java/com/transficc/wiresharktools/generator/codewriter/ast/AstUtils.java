package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.Optional;


import static com.transficc.wiresharktools.generator.GenUtils.camelCase;

public class AstUtils
{
    public static String decodeHeaderFunctionName(final String schemaName)
    {
        return camelCase(schemaName) + "SbeHeader";
    }

    static String protoTypeDeclaration(final String name, final String fieldType, final String fieldName, final Optional<String> base)
    {
        final String abbreviation = abbreviation(fieldName);
        return name +
               " = ProtoField." +
               fieldType +
               "(\"" +
               abbreviation +
               "\", \"" +
               fieldName +
               "\"" +
               base.map(s -> ", " + s).orElse("") +
               ")";
    }

    private static String abbreviation(final String fieldName)
    {
        // Remove unallowed names
        if (fieldName.equals("text"))
        {
            return "field_text";
        }
        return fieldName;
    }
}

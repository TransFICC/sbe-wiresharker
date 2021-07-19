package com.transficc.wiresharktools.generator;

public class GenUtils
{
    public static String fullyQualifiedName(final String schema, final String messageName, final String fieldName)
    {
        if (messageName.isEmpty())
        {
            return schema + "_" + fieldName;
        }
        return schema + "_" +
               messageName + "_" +
               fieldName;
    }

    public static String camelCase(final String value)
    {
        return Character.toLowerCase(value.charAt(0)) + value.substring(1);
    }

    public static String properCase(final String value)
    {
        return Character.toUpperCase(value.charAt(0)) + value.substring(1);
    }
}

package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import com.transficc.wiresharktools.generator.GenUtils;
import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class SchemaDispatcherFunction implements Renderable
{
    private final Map<Integer, String> schemasById = new LinkedHashMap<>();

    public void addSchema(final int schemaId, final String schemaName)
    {
        final String old = schemasById.put(schemaId, schemaName);
        if (old != null)
        {
            throw new IllegalArgumentException("You have provided multiple schemas that have the ID: " + schemaId);
        }
    }

    @Override
    public String render(final Indentation indentation)
    {
        return "function dispatch(buffer, offset, subTree)\n" +
               "    local schemaId = schemaId(buffer, offset)\n" +
               schemaDispatchTable(schemasById) +
               "    return offset\n" +
               "end\n";
    }

    private static String schemaDispatchTable(final Map<Integer, String> schemasById)
    {
        return "    if " +
               schemasById
                       .entrySet()
                       .stream()
                       .map(
                               idAndName ->
                                       "schemaId == " + idAndName.getKey() + " then\n" +
                                       "        offset = decode" + GenUtils.properCase(idAndName.getValue()) + "(buffer, offset, subTree)")
                       .collect(Collectors.joining("\n    elseif ")) + "\n    end\n";
    }
}

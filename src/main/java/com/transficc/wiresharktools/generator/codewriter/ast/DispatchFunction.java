package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.transficc.wiresharktools.generator.GenUtils;
import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class DispatchFunction implements Renderable
{
    private final List<DispatchEntry> entries = new ArrayList<>();
    private final String schemaName;

    public DispatchFunction(final String schemaName)
    {
        this.schemaName = schemaName;
    }

    public void addEntry(final DispatchEntry dispatchEntry)
    {
        entries.add(dispatchEntry);
    }

    @Override
    public String render(final Indentation indentation)
    {
        return "function dispatchTable" + GenUtils.properCase(schemaName) + "(buffer, offset, subtree, templateId, blockLength)\n" +
               indentation.indent() + "if " +
               entries
                       .stream()
                       .map(dispatchEntry -> dispatchEntry.render(indentation.indent()))
                       .collect(Collectors.joining(indentation.indent() + "elseif ")) +
               indentation.indent() + "end\n" +
               indentation.indent() + "return offset\n" +
               "end\n";
    }
}

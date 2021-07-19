package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class HeaderDecodeFunction implements Renderable
{
    private final List<HeaderDecodeStatements> headerDecodeStatements = new ArrayList<>();
    private final String schemaName;

    public HeaderDecodeFunction(final String schemaName)
    {
        this.schemaName = schemaName;
    }

    public void add(final HeaderDecodeStatements headerDecodeStatements)
    {
        this.headerDecodeStatements.add(headerDecodeStatements);
    }

    @Override
    public String render(final Indentation indentation)
    {
        return indentation + "function " + AstUtils.decodeHeaderFunctionName(schemaName) + "(buffer, offset, subtree)\n" +
               headerDecodeStatements.stream().map(headerDecodeStatements -> headerDecodeStatements.render(indentation.indent())).collect(Collectors.joining("\n")) +
               indentation.indent() + "return offset\n" +
               "end";
    }
}

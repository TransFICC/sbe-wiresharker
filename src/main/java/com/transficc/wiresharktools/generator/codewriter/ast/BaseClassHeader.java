package com.transficc.wiresharktools.generator.codewriter.ast;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class BaseClassHeader implements Renderable
{
    private final String protocolTree;
    private final String shortName;
    private final String description;

    public BaseClassHeader(final String protocolTree, final String shortName, final String description)
    {
        this.protocolTree = protocolTree;
        this.shortName = shortName;
        this.description = description;
    }

    @Override
    public String render(final Indentation indentation)
    {
        return protocolTree + " = Proto(\"" + shortName + "\", \"" + description + "\")\n";
    }
}

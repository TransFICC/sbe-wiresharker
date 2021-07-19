package com.transficc.wiresharktools.generator.codewriter.ast;

import com.transficc.wiresharktools.generator.GenUtils;
import com.transficc.wiresharktools.generator.codewriter.Indentation;


import static com.transficc.wiresharktools.generator.GenUtils.camelCase;

public final class ProtocolDecodeFunction implements Renderable
{
    private final String schemaName;
    private final String tree;

    public ProtocolDecodeFunction(final String schemaName, final String tree)
    {
        this.schemaName = schemaName;
        this.tree = tree;
    }

    @Override
    public String render(final Indentation indentation)
    {
        final String subTreeName = camelCase(schemaName) + "HeaderSubTree";
        return indentation + "function decode" + GenUtils.properCase(schemaName) + "(buffer, offset, subtree)\n" +
               indentation.indent() + "local templateId = templateId(buffer, offset)\n" +
               indentation.indent() + "local blockLength = blockLength(buffer, offset)\n" +
               indentation.indent() + "local " + subTreeName + " = subtree:add(" + tree + ", buffer(), \"" + GenUtils.properCase(schemaName) + " Protocol Header\")\n" +
               indentation.indent() + "offset = " + AstUtils.decodeHeaderFunctionName(schemaName) + "(buffer, offset, " + subTreeName + ")\n" +
               indentation.indent() + "offset = dispatchTable" + GenUtils.properCase(schemaName) + "(buffer, offset, " + subTreeName + ", templateId, blockLength)\n" +
               indentation.indent() + "return offset\n" +
               "end";
    }
}

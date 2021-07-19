package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.transficc.wiresharktools.generator.codewriter.CodeWriter;
import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class MessageDecodeFunction implements DecodeFunction
{
    private final List<DecodeStatements> decodeStatements = new ArrayList<>();
    private final String tree;
    private final String subTree;
    private final String decodeMessageFunctionName;
    private final String messageName;
    private final boolean isEnvelope;

    public MessageDecodeFunction(
            final String tree,
            final String subTree,
            final String decodeMessageFunctionName,
            final String messageName,
            final boolean isEnvelope
    )
    {
        this.tree = tree;
        this.subTree = subTree;
        this.decodeMessageFunctionName = decodeMessageFunctionName;
        this.messageName = messageName;
        this.isEnvelope = isEnvelope;
    }

    @Override
    public void add(final DecodeStatements decodeStatements)
    {
        this.decodeStatements.add(decodeStatements);
    }

    @Override
    public String render(final Indentation indentation)
    {
        String body = indentation + "function " + decodeMessageFunctionName + "(buffer, " + CodeWriter.INITIAL_OFFSET_VAR + ", blockLength, subtree)\n" +
                      indentation.indent() + "local offsetToStartOfBlock = " + CodeWriter.INITIAL_OFFSET_VAR + "\n" +
                      indentation.indent() + "local offset = " + CodeWriter.INITIAL_OFFSET_VAR + "\n" +
                      indentation.indent() + "local " + subTree + " = subtree:add(" + tree + ", buffer(), \"" + messageName + "\")\n" +
                      decodeStatements.stream().takeWhile(DecodeStatements::isFixedLength).map(statements -> statements.render(indentation.indent())).collect(Collectors.joining("\n")) + "\n" +
                      indentation.indent() + "offset = blockLength + " + CodeWriter.INITIAL_OFFSET_VAR + "\n" +
                      decodeStatements.stream().dropWhile(DecodeStatements::isFixedLength).map(statements -> statements.render(indentation.indent())).collect(Collectors.joining("\n")) + "\n";
        if (isEnvelope)
        {
            body = body + indentation + "offset = dispatch(buffer, offset, " + subTree + ")\n";
        }
        return body +
               indentation.indent() + "return offset\n" +
               indentation + "end";
    }
}

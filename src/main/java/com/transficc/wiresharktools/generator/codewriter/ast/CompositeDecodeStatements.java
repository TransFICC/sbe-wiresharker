package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class CompositeDecodeStatements implements DecodeStatements, DecodeFunction
{
    private final List<DecodeStatements> decodeStatementsList = new ArrayList<>();
    private final String protoTypeName;
    private final String subTree;
    private final int encodedLength;

    public CompositeDecodeStatements(final String protoTypeName, final String subTree, final int encodedLength)
    {
        this.protoTypeName = protoTypeName;
        this.subTree = subTree;
        this.encodedLength = encodedLength;
    }

    @Override
    public void add(final DecodeStatements decodeStatements)
    {
        decodeStatementsList.add(decodeStatements);
    }

    @Override
    public String render(final Indentation indentation)
    {
        final String above = indentation + "local " + protoTypeName + " = " + subTree + ":add_le(" + protoTypeName + ", buffer(offset, " + encodedLength + "))\n";
        final String middle = decodeStatementsList.stream().map(decodeStatements -> decodeStatements.render(indentation)).collect(Collectors.joining("\n")) + "\n";
        return above + middle;
    }

    @Override
    public boolean isFixedLength()
    {
        return true;
    }
}

package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.transficc.wiresharktools.generator.codewriter.Indentation;


import static com.transficc.wiresharktools.generator.GenUtils.camelCase;

public final class RepeatingGroupDecodeStatements implements DecodeStatements, DecodeFunction
{
    private final List<DecodeStatements> decodeStatementsList = new ArrayList<>();
    private final String protoTypeName;
    private final String subTree;
    private final String fieldName;
    private final int blockLengthFieldOffset;
    private final int blockLengthFieldEncodedLength;
    private final int numInGroupFieldEncodedLength;
    private final int headerLength;
    private final int numInGroupFieldOffset;

    public RepeatingGroupDecodeStatements(
            final String protoTypeName,
            final String subTree,
            final String fieldName,
            final int blockLengthFieldOffset,
            final int blockLengthFieldEncodedLength,
            final int numInGroupFieldOffset,
            final int numInGroupFieldEncodedLength,
            final int headerLength
    )
    {
        this.protoTypeName = protoTypeName;
        this.subTree = subTree;
        this.fieldName = fieldName;
        this.blockLengthFieldOffset = blockLengthFieldOffset;
        this.blockLengthFieldEncodedLength = blockLengthFieldEncodedLength;
        this.numInGroupFieldEncodedLength = numInGroupFieldEncodedLength;
        this.headerLength = headerLength;
        this.numInGroupFieldOffset = numInGroupFieldOffset;
    }

    public void add(final DecodeStatements decodeStatements)
    {
        decodeStatementsList.add(decodeStatements);
    }

    @Override
    public String render(final Indentation indentation)
    {
        final String numInGroupVarName = camelCase(fieldName) + "NumInGroup";
        final String blockLengthVarName = camelCase(fieldName) + "BlockLength";

        final String above = indentation + "local " + numInGroupVarName + " = buffer(offset + " + numInGroupFieldOffset + ", " + numInGroupFieldEncodedLength + "):le_uint()" + "\n" +
                             indentation + "local " + blockLengthVarName + " = buffer(offset + " + blockLengthFieldOffset + ", " + blockLengthFieldEncodedLength + "):le_uint()" + "\n" +
                             indentation + "offset = offset + " + headerLength + "\n" +
                             indentation + "for i=1," + numInGroupVarName + ",1 do" + "\n" +
                             indentation.indent() + "offsetToStartOfBlock = offset\n" +
                             indentation.indent() + "local offsetToEndOfBlock = offset + " + blockLengthVarName + "\n" +
                             indentation.indent() + "local repeatingGroup = " + subTree + ":add_le(" + protoTypeName + ", buffer())" + "\n" +
                             indentation.indent() + "repeatingGroup:set_text(\"" + fieldName + "[\" .. (i-1) .. \"]\")" + "\n";

        final String fixedLengthFields = decodeStatementsList
                                                 .stream()
                                                 .takeWhile(DecodeStatements::isFixedLength)
                                                 .map(decodeStatements -> decodeStatements.render(indentation.indent()))
                                                 .collect(Collectors.joining("\n")) + "\n";

        final String moveOffsetToEndOfFixedLengthFields = indentation.indent() + "offset = offsetToEndOfBlock" + "\n";

        final String variableLengthFields = decodeStatementsList
                                                    .stream()
                                                    .dropWhile(DecodeStatements::isFixedLength)
                                                    .map(decodeStatements -> decodeStatements.render(indentation.indent()))
                                                    .collect(Collectors.joining("\n")) + "\n";
        final String below = indentation + "end";
        return above + fixedLengthFields + moveOffsetToEndOfFixedLengthFields + variableLengthFields + below;
    }

    @Override
    public boolean isFixedLength()
    {
        return false;
    }
}

package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class ChoiceDecodeStatements implements DecodeStatements
{
    private final List<String> choices = new ArrayList<>();
    private final String protoTypeName;
    private final String subTree;
    private final String fieldName;
    private final String choiceTypeName;
    private final int encodedLength;

    public ChoiceDecodeStatements(final String protoTypeName, final String subTree, final String fieldName, final String choiceTypeName, final int encodedLength)
    {
        this.protoTypeName = protoTypeName;
        this.subTree = subTree;
        this.fieldName = fieldName;
        this.choiceTypeName = choiceTypeName;
        this.encodedLength = encodedLength;
    }

    public void addChoice(final String choice)
    {
        choices.add(choice);
    }

    @Override
    public String render(final Indentation indentation)
    {
        final String above = indentation + "local " + protoTypeName + " = " + subTree + ":add_le(" + protoTypeName + ", buffer())\n";
        final String middle = choices
                .stream()
                .map(choice ->
                     {
                         final String uniqueName = fieldName + "_" + choiceTypeName + "_" + choice;
                         return indentation + "local " + uniqueName + " = " + protoTypeName + ":add_le(" + choice + ", buffer(offset, " + encodedLength + "))";
                     }
                ).collect(Collectors.joining("\n"));
        final String end = indentation + "offset = offset + " + encodedLength;
        return above + middle + end;
    }

    @Override
    public boolean isFixedLength()
    {
        return true;
    }
}

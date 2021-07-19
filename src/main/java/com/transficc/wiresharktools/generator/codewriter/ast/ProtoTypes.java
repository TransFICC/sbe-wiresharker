package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class ProtoTypes implements Renderable
{
    final List<ProtoType> protoTypesStrs = new ArrayList<>();

    @Override
    public String render(final Indentation indentation)
    {
        return protoTypesStrs.stream().map(protoType -> protoType.render(indentation)).collect(Collectors.joining("\n"));
    }

    public void add(final ProtoType protoType)
    {
        protoTypesStrs.add(protoType);
    }
}

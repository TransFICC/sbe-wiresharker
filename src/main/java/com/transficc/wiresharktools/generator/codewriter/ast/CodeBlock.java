package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class CodeBlock<T extends Renderable> implements Renderable
{
    private final List<T> subBlocks = new ArrayList<>();

    public void add(final T subBlock)
    {
        subBlocks.add(subBlock);
    }

    @Override
    public String render(final Indentation indentation)
    {
        return subBlocks.stream().map(subBlock -> subBlock.render(indentation)).collect(Collectors.joining("\n\n"));
    }
}

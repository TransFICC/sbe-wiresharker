package com.transficc.wiresharktools.generator.codewriter.ast;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public interface Renderable
{
    String render(final Indentation indentation);
}

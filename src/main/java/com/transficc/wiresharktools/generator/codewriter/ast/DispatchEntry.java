package com.transficc.wiresharktools.generator.codewriter.ast;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class DispatchEntry implements Renderable
{
    private final int templateId;
    private final String messageDecodeFunction;

    public DispatchEntry(final int templateId, final String messageDecodeFunction)
    {
        this.templateId = templateId;
        this.messageDecodeFunction = messageDecodeFunction;
    }

    @Override
    public String render(final Indentation indentation)
    {
        return "templateId == " + templateId + " then\n        offset = " + messageDecodeFunction + "(buffer, offset, blockLength, subtree)\n";
    }
}

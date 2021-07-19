package com.transficc.wiresharktools.generator.codewriter;

public final class Indentation
{
    private static final String TAB = "    ";
    private final String representation;

    public Indentation()
    {
        this("");
    }

    public Indentation(final String init)
    {
        this.representation = init;
    }

    @Override
    public String toString()
    {
        return representation;
    }

    public Indentation indent()
    {
        return new Indentation(representation + TAB);
    }
}

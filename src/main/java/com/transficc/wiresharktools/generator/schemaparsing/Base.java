package com.transficc.wiresharktools.generator.schemaparsing;

public enum Base
{
    DEC("base.DEC"),
    ASCII("base.ASCII"),
    UNICODE("base.UNICODE");

    private final String rendered;

    Base(final String rendered)
    {
        this.rendered = rendered;
    }

    public String render()
    {
        return rendered;
    }
}

package com.transficc.wiresharktools.generator.schemaparsing;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public final class Protocol
{
    private final List<Message> messages = new ArrayList<>();
    private final String schemaName;
    private final int schemaId;
    private final Set<String> envelopes;
    private Composite messageHeader;

    public Protocol(final String schemaName, final int schemaId, final Set<String> envelopes)
    {
        this.schemaName = schemaName;
        this.schemaId = schemaId;
        this.envelopes = Collections.unmodifiableSet(envelopes);
    }

    public List<Message> messages()
    {
        return Collections.unmodifiableList(messages);
    }

    public String name()
    {
        return schemaName;
    }

    public Collection<String> envelopes()
    {
        return envelopes;
    }

    public Integer id()
    {
        return schemaId;
    }

    public void addMessage(final Message message)
    {
        messages.add(message);
    }

    public void messageHeader(final Composite messageHeader)
    {
        this.messageHeader = messageHeader;
    }

    public Composite messageHeader()
    {
        return messageHeader;
    }
}

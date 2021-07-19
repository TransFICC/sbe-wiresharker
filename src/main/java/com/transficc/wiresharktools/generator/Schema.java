package com.transficc.wiresharktools.generator;

import java.util.Collections;
import java.util.Set;


import uk.co.real_logic.sbe.xml.MessageSchema;

public final class Schema
{
    public final MessageSchema messageSchema;
    public final String schemaName;
    public final Set<String> envelopes;

    private Schema(final MessageSchema messageSchema, final String schemaName, final Set<String> envelopes)
    {
        this.messageSchema = messageSchema;
        this.schemaName = schemaName;
        this.envelopes = Collections.unmodifiableSet(envelopes);
    }

    public static Schema schema(final MessageSchema messageSchema, final String schemaName, final Set<String> envelopes)
    {
        for (int i = 0; i < schemaName.length(); i++)
        {
            final char c = schemaName.charAt(i);
            if (!Character.isAlphabetic(c))
            {
                throw new IllegalArgumentException("Schema name cannot contain special chars: " + schemaName);
            }
        }
        return new Schema(messageSchema, schemaName, envelopes);
    }
}

package com.transficc.wiresharktools.generator;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import com.transficc.wiresharktools.generator.codewriter.CodeWriter;
import com.transficc.wiresharktools.generator.schemaparsing.Protocol;
import com.transficc.wiresharktools.generator.schemaparsing.SchemaParser;


import uk.co.real_logic.sbe.xml.MessageSchema;

@SuppressWarnings("ObjectAllocationInLoop")
public class SbeLuaGenerator
{

    public static void generateLuaDissector(
            final String protocolTree,
            final String protocolShortName,
            final String protocolDescription,
            final OutputStream out,
            final Frame frame,
            final int[] ports,
            final Schema... schemas
    )
    {
        final List<Protocol> protocols = new ArrayList<>();
        for (final Schema schema : schemas)
        {
            final Protocol protocol = new Protocol(schema.schemaName, schema.messageSchema.id(), schema.envelopes);
            final MessageSchema messageSchema = schema.messageSchema;
            SchemaParser.generateSchemaCode(messageSchema, protocol);
            protocols.add(protocol);
        }

        CodeWriter.write(protocolTree, protocolShortName, protocolDescription, out, protocols, frame, ports);
    }

}

package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.Arrays;
import java.util.stream.Collectors;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class LuaBaseCode implements Renderable
{
    private final SchemaDispatcherFunction schemaDispatchFunction;
    private final String protocolTree;
    private final String protocolDescription;
    private final int[] ports;
    private final int frameLengthEncodingLength;
    private final int frameAdditionalBytes;
    private final int frameOffsetToLength;
    private final boolean lengthIncludesFrame;

    public LuaBaseCode(
            final SchemaDispatcherFunction schemaDispatchFunction,
            final String protocolTree,
            final String protocolDescription,
            final int[] ports,
            final int frameLengthEncodingLength,
            final int frameAdditionalBytes,
            final int frameOffsetToLength,
            final boolean lengthIncludesFrame
    )
    {
        this.schemaDispatchFunction = schemaDispatchFunction;
        this.protocolTree = protocolTree;
        this.protocolDescription = protocolDescription;
        this.ports = ports;
        this.frameLengthEncodingLength = frameLengthEncodingLength;
        this.frameAdditionalBytes = frameAdditionalBytes;
        this.frameOffsetToLength = frameOffsetToLength;
        this.lengthIncludesFrame = lengthIncludesFrame;
    }

    @Override
    public String render(final Indentation indentation)
    {
        final String reduceMessageLengthByFrameSize;
        if (lengthIncludesFrame)
        {
            reduceMessageLengthByFrameSize = indentation.indent().indent() + "sizeOfMessage = sizeOfMessage - frameSize\n";
        }
        else
        {
            reduceMessageLengthByFrameSize = "";
        }
        return indentation + "function " + protocolTree + ".dissector(buffer, pinfo, tree)\n" +
               indentation.indent() + "local offsetToPayload = 0\n" +
               indentation.indent() + "while offsetToPayload < buffer:len() do\n" +
               indentation.indent().indent() + "local length = buffer:len() - offsetToPayload\n" +
               indentation.indent().indent() + "local frameSize = " + (frameOffsetToLength + frameLengthEncodingLength + frameAdditionalBytes) + "\n" +
               indentation.indent().indent() + "if length < frameSize then\n" +
               indentation.indent().indent().indent() + "pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT\n" +
               indentation.indent().indent().indent() + "pinfo.desegment_offset = offsetToPayload\n" +
               indentation.indent().indent().indent() + "return\n" +
               indentation.indent().indent() + "end\n" +
               indentation.indent().indent() + "local remainingData = length - frameSize\n" +
               indentation.indent().indent() + "local sizeOfMessage = buffer(offsetToPayload + " + frameOffsetToLength + ", " + frameLengthEncodingLength + "):le_int()\n" +
               reduceMessageLengthByFrameSize +
               indentation.indent().indent() + "if sizeOfMessage > remainingData then\n" +
               indentation.indent().indent().indent() + "pinfo.desegment_len = sizeOfMessage - remainingData\n" +
               indentation.indent().indent().indent() + "pinfo.desegment_offset = offsetToPayload\n" +
               indentation.indent().indent().indent() + "return\n" +
               indentation.indent().indent() + "end\n" +
               indentation.indent().indent() + "\n" +
               indentation.indent().indent() + "pinfo.cols.protocol = " + protocolTree + ".name\n" +
               indentation.indent().indent() + "\n" +
               indentation.indent().indent() + "local protocolRootTree = tree:add(" + protocolTree + ", buffer(offsetToPayload, frameSize + remainingData), \"" + protocolDescription + "\")\n" +
               indentation.indent().indent() + "\n" +
               indentation.indent().indent() + "local frameSubTree = protocolRootTree:add(" + protocolTree + ", buffer(offsetToPayload, frameSize), \"Frame\")\n" +
               indentation.indent().indent() + "frameSubTree:add_le(" + "messageLength" + ", buffer(offsetToPayload + " + frameOffsetToLength + ", " + frameLengthEncodingLength + "))\n" +
               indentation.indent().indent() + "\n" +
               indentation.indent().indent() + "dispatch(buffer, offsetToPayload + frameSize, frameSubTree)\n" +
               indentation.indent().indent() + "offsetToPayload = offsetToPayload + frameSize + sizeOfMessage\n" +
               indentation.indent() + "end\n" +
               indentation + "end\n" +
               indentation + "\n" +
               schemaDispatchFunction.render(indentation) +
               "\n" +
               blockLengthFunction() +
               "\n" +
               schemaIdFunction() +
               "\n" +
               templateIdFunction() +
               "\n" +
               portsAssignment(protocolTree, ports);
    }

    private static String templateIdFunction()
    {
        return "function templateId(buffer, offset)\n" +
               "    return buffer(offset + 2, 2):le_uint()\n" +
               "end\n";
    }

    private static String schemaIdFunction()
    {
        return "function schemaId(buffer, offset)\n" +
               "    return buffer(offset + 4, 2):le_uint()\n" +
               "end\n";
    }

    private static String blockLengthFunction()
    {
        return "function blockLength(buffer, offset)\n" +
               "    return buffer(offset + 0, 2):le_uint()\n" +
               "end\n";
    }

    private static String portsAssignment(final String protocolTree, final int[] ports)
    {
        final String portAssignment;
        if (ports.length > 0)
        {
            portAssignment = "local tcp_port = DissectorTable.get(\"tcp.port\")\n" +
                             Arrays
                                     .stream(ports)
                                     .mapToObj(port -> "tcp_port:add(" + port + ", " + protocolTree + ")")
                                     .collect(Collectors.joining("\n"));
        }
        else
        {
            portAssignment = "";
        }
        return portAssignment;
    }
}

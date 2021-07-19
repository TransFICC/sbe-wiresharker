package com.transficc.wiresharktools.generator.codewriter.ast;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.transficc.wiresharktools.generator.codewriter.Indentation;

public final class LuaScript
{
    private LuaScript()
    {
        throw new UnsupportedOperationException("Do not instantiate me");
    }

    public static String render(
            final BaseClassHeader baseClassHeader,
            final ProtoTypes protoTypes,
            final FieldsDeclaration fieldsDeclaration,
            final LuaBaseCode luaBaseCode,
            final CodeBlock<HeaderDecodeFunction> headerDecodeFunctions,
            final CodeBlock<ProtocolDecodeFunction> protocolDecodeFunctions,
            final CodeBlock<DispatchFunction> dispatchTables,
            final CodeBlock<MessageDecodeFunction> messageDecodeFunctions
    )
    {
        final Indentation indentation = new Indentation();
        return Stream
                .of(
                        baseClassHeader,
                        protoTypes,
                        fieldsDeclaration,
                        luaBaseCode,
                        headerDecodeFunctions,
                        protocolDecodeFunctions,
                        dispatchTables,
                        messageDecodeFunctions
                )
                .map(renderable -> renderable.render(indentation))
                .collect(Collectors.joining("\n\n"));
    }
}

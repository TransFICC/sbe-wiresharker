package com.transficc.wiresharktools.generator.codewriter;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.transficc.wiresharktools.generator.Frame;
import com.transficc.wiresharktools.generator.GenUtils;
import com.transficc.wiresharktools.generator.codewriter.ast.ArrayDecodeStatements;
import com.transficc.wiresharktools.generator.codewriter.ast.BaseClassHeader;
import com.transficc.wiresharktools.generator.codewriter.ast.BasicDecodeStatements;
import com.transficc.wiresharktools.generator.codewriter.ast.BitFieldProtoType;
import com.transficc.wiresharktools.generator.codewriter.ast.ChoiceDecodeStatements;
import com.transficc.wiresharktools.generator.codewriter.ast.CodeBlock;
import com.transficc.wiresharktools.generator.codewriter.ast.CompositeDecodeStatements;
import com.transficc.wiresharktools.generator.codewriter.ast.ConstantDecodeStatements;
import com.transficc.wiresharktools.generator.codewriter.ast.DecodeFunction;
import com.transficc.wiresharktools.generator.codewriter.ast.DispatchEntry;
import com.transficc.wiresharktools.generator.codewriter.ast.DispatchFunction;
import com.transficc.wiresharktools.generator.codewriter.ast.EnumProtoType;
import com.transficc.wiresharktools.generator.codewriter.ast.FieldsDeclaration;
import com.transficc.wiresharktools.generator.codewriter.ast.HeaderDecodeFunction;
import com.transficc.wiresharktools.generator.codewriter.ast.HeaderDecodeStatements;
import com.transficc.wiresharktools.generator.codewriter.ast.LuaBaseCode;
import com.transficc.wiresharktools.generator.codewriter.ast.LuaScript;
import com.transficc.wiresharktools.generator.codewriter.ast.MessageDecodeFunction;
import com.transficc.wiresharktools.generator.codewriter.ast.ProtoTypes;
import com.transficc.wiresharktools.generator.codewriter.ast.ProtocolDecodeFunction;
import com.transficc.wiresharktools.generator.codewriter.ast.RepeatingGroupDecodeStatements;
import com.transficc.wiresharktools.generator.codewriter.ast.SchemaDispatcherFunction;
import com.transficc.wiresharktools.generator.codewriter.ast.SimpleProtoType;
import com.transficc.wiresharktools.generator.codewriter.ast.SyntheticProtoType;
import com.transficc.wiresharktools.generator.codewriter.ast.VarLengthDecodeStatements;
import com.transficc.wiresharktools.generator.codewriter.ast.VarLengthStringProtoType;
import com.transficc.wiresharktools.generator.schemaparsing.CharacterArray;
import com.transficc.wiresharktools.generator.schemaparsing.Choice;
import com.transficc.wiresharktools.generator.schemaparsing.Composite;
import com.transficc.wiresharktools.generator.schemaparsing.Constant;
import com.transficc.wiresharktools.generator.schemaparsing.ConstantEnumeration;
import com.transficc.wiresharktools.generator.schemaparsing.Enumeration;
import com.transficc.wiresharktools.generator.schemaparsing.Field;
import com.transficc.wiresharktools.generator.schemaparsing.Group;
import com.transficc.wiresharktools.generator.schemaparsing.Message;
import com.transficc.wiresharktools.generator.schemaparsing.PrimitiveArray;
import com.transficc.wiresharktools.generator.schemaparsing.Protocol;
import com.transficc.wiresharktools.generator.schemaparsing.SimpleType;
import com.transficc.wiresharktools.generator.schemaparsing.VariableLengthData;


import static com.transficc.wiresharktools.generator.GenUtils.camelCase;
import static java.util.stream.Collectors.toMap;

@SuppressWarnings({"CollectionWithoutInitialCapacity"})
public class CodeWriter
{
    public static final String INITIAL_OFFSET_VAR = "initialOffset";

    public static void write(
            final String protocolTree,
            final String protocolShortName,
            final String protocolDescription,
            final OutputStream out,
            final List<Protocol> protocols,
            final Frame frame,
            final int[] ports
    )
    {
        final ProtoTypes protoTypes = new ProtoTypes();
        final FieldsDeclaration fieldsDeclaration = new FieldsDeclaration(protocolTree);
        final CodeBlock<MessageDecodeFunction> messageDecodeFunctions = new CodeBlock<>();
        final CodeBlock<DispatchFunction> dispatchTables = new CodeBlock<>();
        final CodeBlock<HeaderDecodeFunction> headerDecodeFunctions = new CodeBlock<>();
        final CodeBlock<ProtocolDecodeFunction> protocolDecodeFunctions = new CodeBlock<>();
        for (final Protocol protocol : protocols)
        {
            generateProtocol(
                    protocol,
                    protocolTree,
                    protoTypes,
                    fieldsDeclaration,
                    messageDecodeFunctions,
                    dispatchTables,
                    headerDecodeFunctions,
                    protocolDecodeFunctions
            );
        }
        final BaseClassHeader baseClassHeader = new BaseClassHeader(protocolTree, protocolShortName, protocolDescription);
        addFrameHeader(protoTypes, fieldsDeclaration, frame.messageLengthType());
        final SchemaDispatcherFunction schemaDispatcherFunction = schemaDispatcherFunction(protocols.stream().collect(toMap(Protocol::id, Protocol::name)));
        final LuaBaseCode luaBaseCode = new LuaBaseCode(
                schemaDispatcherFunction,
                protocolTree,
                protocolDescription,
                ports,
                frame.messageLengthType().lengthInBytes(),
                frame.additionalDataInFrameLength(),
                frame.offsetToMessageLength(),
                frame.lengthIncludesFrame()
        );

        final String output = LuaScript.render(
                baseClassHeader,
                protoTypes,
                fieldsDeclaration,
                luaBaseCode,
                headerDecodeFunctions,
                protocolDecodeFunctions,
                dispatchTables,
                messageDecodeFunctions
        );

        write(output, out);
    }

    private static void generateProtocol(
            final Protocol protocol,
            final String protocolTree,
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final CodeBlock<MessageDecodeFunction> messageDecodeFunctions,
            final CodeBlock<DispatchFunction> dispatchTables,
            final CodeBlock<HeaderDecodeFunction> headerDecodeFunctions,
            final CodeBlock<ProtocolDecodeFunction> protocolDecodeFunctions
    )
    {
        final Indentation indentation = new Indentation("");
        protocolDecodeFunctions.add(new ProtocolDecodeFunction(protocol.name(), protocolTree));
        parseSbeHeader(protocol, protoTypes, fields, headerDecodeFunctions);
        final DispatchFunction dispatchFunction = new DispatchFunction(protocol.name());
        final Set<String> enumsMapped = new HashSet<>();
        for (final Message message : protocol.messages())
        {
            final String decodeFunctionName = decodeFunctionName(protocol.name(), message.name());
            final String messageNameCamel = camelCase(message.name());
            final String subTree = messageNameCamel + "SubTree";
            final boolean isEnvelope = protocol.envelopes().contains(message.name());
            final MessageDecodeFunction messageDecodeFunction = new MessageDecodeFunction(protocolTree, subTree, decodeFunctionName, message.name(), isEnvelope);
            for (final Field field : message.fields())
            {
                parseField(protoTypes, fields, enumsMapped, subTree, messageDecodeFunction, field, indentation, protocol.name());
            }
            messageDecodeFunctions.add(messageDecodeFunction);
            dispatchFunction.addEntry(new DispatchEntry(message.id(), decodeFunctionName));
        }
        dispatchTables.add(dispatchFunction);
    }

    private static void parseSbeHeader(
            final Protocol protocol,
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final CodeBlock<HeaderDecodeFunction> headerDecodeFunctions
    )
    {
        addSbeHeaders(protoTypes, fields, protocol.messageHeader());
        headerDecodeFunction(protocol.name(), headerDecodeFunctions, protocol.messageHeader());
    }

    private static void addSbeHeaders(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final Composite composite
    )
    {
        for (final Field field : composite.fields())
        {
            final SimpleType simpleType = field.simpleType();
            protoTypes.add(new SimpleProtoType(field.fullyQualifiedName(), field.name(), simpleType.fieldType(), simpleType.base()));
            fields.add(field.fullyQualifiedName());
        }
    }

    private static void addFrameHeader(final ProtoTypes protoTypes, final FieldsDeclaration fields, final SimpleType messageLengthType)
    {
        protoTypes.add(new SimpleProtoType("messageLength", "messageLength", messageLengthType.fieldType(), messageLengthType.base()));
        fields.add("messageLength");
    }

    private static void parseField(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final Set<String> enumsMapped,
            final String subTree,
            final DecodeFunction decodeFunction,
            final Field field,
            final Indentation indentation,
            final String schemaName
    )
    {
        if (field.isSimpleType())
        {
            parseSimpleType(protoTypes, fields, subTree, decodeFunction, field);
        }
        else if (field.complexType() instanceof Enumeration)
        {
            parseEnumType(protoTypes, fields, enumsMapped, subTree, decodeFunction, field, schemaName, (Enumeration)field.complexType());
        }
        else if (field.complexType() instanceof Composite)
        {
            parseComposite(protoTypes, fields, enumsMapped, subTree, decodeFunction, field, indentation, schemaName, (Composite)field.complexType());
        }
        else if (field.complexType() instanceof CharacterArray)
        {
            parseCharacterArray(protoTypes, fields, subTree, decodeFunction, field, (CharacterArray)field.complexType());
        }
        else if (field.complexType() instanceof Choice)
        {
            parseChoice(protoTypes, fields, subTree, decodeFunction, field, (Choice)field.complexType());
        }
        else if (field.complexType() instanceof PrimitiveArray)
        {
            parseArrayType(protoTypes, fields, subTree, decodeFunction, field, (PrimitiveArray)field.complexType());
        }
        else if (field.complexType() instanceof VariableLengthData)
        {
            parseVariableLengthData(protoTypes, fields, subTree, decodeFunction, field, (VariableLengthData)field.complexType());
        }
        else if (field.complexType() instanceof Group)
        {
            parseRepeatingGroup(protoTypes, fields, enumsMapped, subTree, decodeFunction, field, indentation, schemaName, (Group)field.complexType());
        }
        else if (field.complexType() instanceof Constant)
        {
            parseConstant(protoTypes, fields, subTree, decodeFunction, field, (Constant)field.complexType());
        }
        else if (field.complexType() instanceof ConstantEnumeration)
        {
            parseConstantEnum(protoTypes, fields, enumsMapped, subTree, decodeFunction, field, schemaName, (ConstantEnumeration)field.complexType());
        }
        else
        {
            throw new UnsupportedOperationException("Could not identify type: \"" + field.name() + "\"");
        }
    }

    private static void parseConstantEnum(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final Set<String> enumsMapped,
            final String subTree,
            final DecodeFunction decodeMessageStatements,
            final Field field,
            final String schemaName,
            final ConstantEnumeration constantEnumeration
    )
    {
        final String treeRoot = field.fullyQualifiedName();
        protoTypes.add(protoTypeDeclarationEnum(constantEnumeration.simpleType(), camelCase(field.name()), treeRoot, field.name(), enumsMapped, constantEnumeration.mapping(), schemaName));
        fields.add(treeRoot);
        decodeMessageStatements.add(new ConstantDecodeStatements(treeRoot, subTree, String.valueOf(constantEnumeration.key())));
    }

    private static void parseConstant(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final String subTree,
            final DecodeFunction decodeMessageStatements,
            final Field field,
            final Constant constant
    )
    {
        final String treeRoot = field.fullyQualifiedName();
        final SimpleType simpleType = constant.simpleType();
        protoTypes.add(new SimpleProtoType(treeRoot, field.name(), simpleType.fieldType(), simpleType.base()));
        fields.add(treeRoot);
        final String value = simpleType == SimpleType.STRING ? '"' + constant.value() + '"' : constant.value();
        decodeMessageStatements.add(new ConstantDecodeStatements(treeRoot, subTree, value));
    }

    private static void parseRepeatingGroup(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final Set<String> enumsMapped,
            final String subTree,
            final DecodeFunction decodeMessageStatements,
            final Field field,
            final Indentation indentation,
            final String schemaName,
            final Group group
    )
    {
        final String treeRoot = field.fullyQualifiedName();

        protoTypes.add(new SyntheticProtoType(treeRoot, field.name()));
        fields.add(treeRoot);
        final RepeatingGroupDecodeStatements repeatingGroupDecodeStatements = new RepeatingGroupDecodeStatements(
                treeRoot,
                subTree,
                field.name(),
                group.offsetBeforeBlockLength(),
                group.blockLength().lengthInBytes(),
                group.offsetBeforeNumInGroup(),
                group.numInGroup().lengthInBytes(),
                group.headerLength()
        );
        for (final Field subField : group.fields())
        {
            parseField(
                    protoTypes,
                    fields,
                    enumsMapped,
                    "repeatingGroup",
                    repeatingGroupDecodeStatements,
                    subField,
                    indentation.indent(),
                    schemaName
            );
        }
        decodeMessageStatements.add(repeatingGroupDecodeStatements);
    }

    private static void parseChoice(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final String subTree,
            final DecodeFunction decodeMessageStatements,
            final Field field,
            final Choice choice
    )
    {
        final String treeRoot = field.fullyQualifiedName();
        protoTypes.add(new SyntheticProtoType(treeRoot, field.name()));
        fields.add(treeRoot);

        final ChoiceDecodeStatements choiceDecodeStatements = new ChoiceDecodeStatements(treeRoot, subTree, field.name(), choice.name(), choice.simpleType().lengthInBytes());
        for (final Map.Entry<Long, String> positionAndName : choice.mapping().entrySet())
        {
            final String choiceName = field.fullyQualifiedName() + "_" + positionAndName.getValue();
            final SimpleType simpleType = choice.simpleType();
            protoTypes.add(new BitFieldProtoType(choiceName, positionAndName.getValue(), simpleType.base(), "True", "False", simpleType.fieldType(), Math.toIntExact(positionAndName.getKey())));
            fields.add(choiceName);
            choiceDecodeStatements.addChoice(choiceName);
        }
        decodeMessageStatements.add(choiceDecodeStatements);
    }

    private static void parseEnumType(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final Set<String> enumsMapped,
            final String subTree,
            final DecodeFunction decodeMessageStatements,
            final Field field,
            final String schemaName, final Enumeration enumeration
    )
    {
        final String fullyQualifiedName;
        final SimpleType simpleType = enumeration.simpleType();
        fullyQualifiedName = field.fullyQualifiedName();
        fields.add(fullyQualifiedName);
        protoTypes.add(protoTypeDeclarationEnum(simpleType, camelCase(field.name()), fullyQualifiedName, field.name(), enumsMapped, enumeration.mapping(), schemaName));
        decodeMessageStatements.add(new BasicDecodeStatements(field.fullyQualifiedName(), subTree, enumeration.simpleType().lengthInBytes(), field.offset()));
    }

    private static void parseSimpleType(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final String subTree,
            final DecodeFunction decodeFunction,
            final Field field
    )
    {
        parseSimpleType(protoTypes, fields, subTree, decodeFunction, field, field.simpleType().lengthInBytes(), field.simpleType());
    }

    private static void parseArrayType(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final String subTree,
            final DecodeFunction decodeFunction,
            final Field field,
            final PrimitiveArray primitiveArray
    )
    {
        final String fullyQualifiedName;
        final String fieldName = camelCase(field.name());

        fullyQualifiedName = field.fullyQualifiedName();
        fields.add(fullyQualifiedName);
        final SimpleType simpleType = primitiveArray.simpleType();
        protoTypes.add(new SimpleProtoType(fullyQualifiedName, fieldName, simpleType.fieldType(), simpleType.base()));
        decodeFunction.add(new ArrayDecodeStatements(field.fullyQualifiedName(), subTree, field.name(), primitiveArray.simpleType().lengthInBytes(), field.offset(), primitiveArray.length()));
    }

    private static void parseSimpleType(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final String subTree,
            final DecodeFunction decodeFunction,
            final Field field,
            final int encodedLength,
            final SimpleType simpleType
    )
    {
        final String fullyQualifiedName;
        final String fieldName = camelCase(field.name());

        fullyQualifiedName = field.fullyQualifiedName();
        fields.add(fullyQualifiedName);
        protoTypes.add(new SimpleProtoType(fullyQualifiedName, fieldName, simpleType.fieldType(), simpleType.base()));
        decodeFunction.add(new BasicDecodeStatements(field.fullyQualifiedName(), subTree, encodedLength, field.offset()));
    }

    private static void parseCharacterArray(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final String subTree,
            final DecodeFunction decodeFunction,
            final Field field,
            final CharacterArray characterArray
    )
    {
        parseSimpleType(protoTypes, fields, subTree, decodeFunction, field, characterArray.length(), characterArray.simpleType());
    }

    private static void parseComposite(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final Set<String> enumsMapped,
            final String subTree,
            final DecodeFunction decodeFunction,
            final Field field,
            final Indentation indentation,
            final String schemaName,
            final Composite composite
    )
    {
        final String treeRoot = field.fullyQualifiedName();
        protoTypes.add(new SyntheticProtoType(treeRoot, field.name()));
        fields.add(treeRoot);
        final CompositeDecodeStatements compositeDecodeStatements = new CompositeDecodeStatements(treeRoot, subTree, composite.encodedLength());
        for (final Field subField : composite.fields())
        {
            parseField(
                    protoTypes,
                    fields,
                    enumsMapped,
                    treeRoot,
                    compositeDecodeStatements,
                    subField,
                    indentation,
                    schemaName
            );
        }
        decodeFunction.add(compositeDecodeStatements);
    }

    private static void parseVariableLengthData(
            final ProtoTypes protoTypes,
            final FieldsDeclaration fields,
            final String subTree,
            final DecodeFunction decodeFunction,
            final Field field,
            final VariableLengthData variableLengthData
    )
    {
        final int lengthFieldEncodedLength = variableLengthData.lengthType().lengthInBytes();
        final String encoding = variableLengthData.dataEncodingType().render();

        protoTypes.add(new VarLengthStringProtoType(field.fullyQualifiedName(), field.name(), encoding));
        fields.add(field.fullyQualifiedName());
        decodeFunction.add(new VarLengthDecodeStatements(field.fullyQualifiedName(), subTree, lengthFieldEncodedLength));
    }

    private static String decodeFunctionName(final String schemaName, final String messageName)
    {
        return "decode_" + schemaName + "_" + GenUtils.camelCase(messageName);
    }

    private static EnumProtoType protoTypeDeclarationEnum(
            final SimpleType simpleType,
            final String fieldName,
            final String fullyQualifiedName,
            final String enumName,
            final Set<String> enumsMapped,
            final Map<Long, String> mapping,
            final String schemaName
    )
    {
        return new EnumProtoType(fieldName, fullyQualifiedName, enumName, enumsMapped, mapping, schemaName, simpleType.fieldType(), simpleType.base());
    }

    private static void write(final String output, final OutputStream out)
    {
        try
        {
            out.write(output.getBytes(StandardCharsets.UTF_8));
        }
        catch (final IOException e)
        {
            throw new UncheckedIOException(e);
        }
    }

    private static SchemaDispatcherFunction schemaDispatcherFunction(final Map<Integer, String> schemaNameById)
    {
        final SchemaDispatcherFunction schemaDispatcherFunction = new SchemaDispatcherFunction();
        schemaNameById.forEach(schemaDispatcherFunction::addSchema);
        return schemaDispatcherFunction;
    }

    private static void headerDecodeFunction(
            final String schemaName,
            final CodeBlock<HeaderDecodeFunction> headerDecodeFunctions,
            final Composite messageHeader
    )
    {
        final HeaderDecodeFunction headerDecodeFunction = new HeaderDecodeFunction(schemaName);
        messageHeader
                .fields()
                .stream()
                .map(field -> new HeaderDecodeStatements(field.fullyQualifiedName(), field.simpleType().lengthInBytes()))
                .forEach(headerDecodeFunction::add);
        headerDecodeFunctions.add(headerDecodeFunction);
    }
}

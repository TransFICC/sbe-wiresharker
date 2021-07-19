package com.transficc.wiresharktools.generator.schemaparsing;

import java.util.List;
import java.util.function.BiConsumer;

import com.transficc.wiresharktools.generator.GenUtils;


import uk.co.real_logic.sbe.PrimitiveType;
import uk.co.real_logic.sbe.ir.Token;
import uk.co.real_logic.sbe.xml.CompositeType;
import uk.co.real_logic.sbe.xml.EncodedDataType;
import uk.co.real_logic.sbe.xml.EnumType;
import uk.co.real_logic.sbe.xml.MessageSchema;
import uk.co.real_logic.sbe.xml.Presence;
import uk.co.real_logic.sbe.xml.SetType;
import uk.co.real_logic.sbe.xml.Type;

public class SchemaParser
{
    public static void generateSchemaCode(
            final MessageSchema messageSchema,
            final Protocol protocol
    )
    {
        final Composite messageHeader = buildComposite(
                protocol.name(),
                GenUtils.camelCase(protocol.name()),
                "MessageHeader",
                messageSchema.messageHeader().getTypeList(),
                messageSchema.messageHeader().encodedLength()
        );
        protocol.messageHeader(messageHeader);
        for (final uk.co.real_logic.sbe.xml.Message sbeMessage : messageSchema.messages())
        {
            final Message message = new Message(sbeMessage.id(), sbeMessage.name());
            protocol.addMessage(message);
            parseMessage(protocol.name(), sbeMessage.name(), sbeMessage.fields(), message);
        }
    }

    private static void parseMessage(
            final String schema,
            final String messageName,
            final List<uk.co.real_logic.sbe.xml.Field> fieldList,
            final Message message
    )
    {
        final String messageNameCamel = GenUtils.camelCase(messageName);
        for (final uk.co.real_logic.sbe.xml.Field field : fieldList)
        {
            final Type type = field.type();
            final String name = field.name();
            final int offset = field.offset();
            final boolean isVariableLength = field.isVariableLength();
            parseField(schema, messageNameCamel, type, name, offset, isVariableLength, field, message);
        }
    }

    private static void parseGroup(
            final String schema,
            final String messageNameCamel,
            final String name,
            final CompositeType groupDimension,
            final List<uk.co.real_logic.sbe.xml.Field> fields,
            final FieldBundle fieldBundle
    )
    {
        final List<Type> typeList = groupDimension.getTypeList();
        final Pair<EncodedDataType, Integer> blockLengthAndOffset = dataTypeAndOffset(typeList, "blockLength");
        final Pair<EncodedDataType, Integer> numInGroupAndOffset = dataTypeAndOffset(typeList, "numInGroup");

        final int dimensionHeaderLength = typeList
                .stream()
                .mapToInt(Type::encodedLength)
                .sum();

        final Group group = new Group(
                blockLengthAndOffset.right,
                simpleType(blockLengthAndOffset.left.primitiveType()),
                numInGroupAndOffset.right,
                simpleType(numInGroupAndOffset.left.primitiveType()),
                dimensionHeaderLength
        );

        fieldBundle.addField(new Field(group, name, 0, GenUtils.fullyQualifiedName(schema, messageNameCamel, name)));

        for (final uk.co.real_logic.sbe.xml.Field field : fields)
        {
            parseField(
                    schema,
                    messageNameCamel + "_" + GenUtils.camelCase(name),
                    field.type(),
                    field.name(),
                    field.offset(),
                    field.isVariableLength(),
                    field,
                    group
            );
        }
    }

    private static Pair<EncodedDataType, Integer> dataTypeAndOffset(final List<Type> typeList, final String name)
    {
        final Pair<EncodedDataType, Integer> dataTypeAndOffset;
        EncodedDataType dataType = null;
        int offsetToDataType = 0;
        for (final Type type : typeList)
        {
            if (name.equals(type.name()))
            {
                dataType = (EncodedDataType)type;
                break;
            }
            offsetToDataType += type.encodedLength();
        }
        if (dataType == null)
        {
            throw new IllegalStateException("Could not find " + name + " in group dimensions: " + typeList);
        }
        dataTypeAndOffset = new Pair<>(dataType, offsetToDataType);
        return dataTypeAndOffset;
    }

    private static void parseField(
            final String schema,
            final String messageNameCamel,
            final Type type,
            final String name,
            final int offset,
            final boolean isVariableLength,
            final uk.co.real_logic.sbe.xml.Field field,
            final FieldBundle fieldBundle
    )
    {
        if (type instanceof EncodedDataType)
        {
            final EncodedDataType encodedDataType = (EncodedDataType)type;
            parseEncodedDataType(schema, messageNameCamel, encodedDataType, name, offset, fieldBundle);
        }
        else if (type instanceof EnumType)
        {
            final EnumType encodedDataType = (EnumType)type;
            if (field == null)
            {
                parseEnumType(schema, messageNameCamel, null, encodedDataType, name, offset, fieldBundle, false);
            }
            else
            {
                parseEnumType(schema, messageNameCamel, field.valueRef(), encodedDataType, name, offset, fieldBundle, field.presence() == Presence.CONSTANT);
            }
        }
        else if (type instanceof CompositeType)
        {
            final CompositeType encodedDataType = (CompositeType)type;
            parseComposite(schema, encodedDataType, messageNameCamel, name, offset, isVariableLength, fieldBundle);
        }
        else if (type instanceof SetType)
        {
            final SetType setType = (SetType)type;
            final SimpleType simpleType = simpleType(setType.encodingType());
            final Choice choiceType = new Choice(simpleType, setType.name(), offset);
            for (final SetType.Choice choice : setType.choices())
            {
                choiceType.addMapping(choice.primitiveValue().longValue(), choice.name());
            }
            fieldBundle.addField(new Field(choiceType, name, offset, GenUtils.fullyQualifiedName(schema, messageNameCamel, name)));

        }
        else if (type == null && field != null)
        {
            parseGroup(schema, messageNameCamel, name, field.dimensionType(), field.groupFields(), fieldBundle);
        }
        else
        {
            throw new UnsupportedOperationException("Could not identify type \"" + type + "\": " + type);
        }
    }

    private static void parseEnumType(
            final String schema, final String messageNameCamel,
            final String constantValue,
            final EnumType enumType,
            final String name,
            final int offset,
            final FieldBundle fieldBundle,
            final boolean isConstant
    )
    {
        final PrimitiveType primitiveType = enumType.encodingType();
        final SimpleType simpleType = enumSimpleType(primitiveType);
        final String fieldName = GenUtils.camelCase(name);

        final ComplexType complexType;
        final BiConsumer<Long, String> mappingConsumer;
        if (isConstant && constantValue != null)
        {
            final String constant = constantValue.split("\\.", 2)[1];
            final long enumKey = enumType
                    .validValues()
                    .stream()
                    .filter(validValue -> validValue.name().equals(constant))
                    .map(validValue -> validValue.primitiveValue().longValue())
                    .findAny()
                    .orElseThrow(() -> new IllegalStateException("Couldn't find enum constant for: " + constantValue));

            final ConstantEnumeration constantEnumeration = new ConstantEnumeration(simpleType, constant, enumKey);
            mappingConsumer = constantEnumeration::addMapping;
            complexType = constantEnumeration;
        }
        else
        {
            final Enumeration enumeration = new Enumeration(simpleType, offset);
            mappingConsumer = enumeration::addMapping;
            complexType = enumeration;
        }
        enumType.validValues().forEach(validValue -> mappingConsumer.accept(validValue.primitiveValue().longValue(), validValue.name()));
        fieldBundle.addField(new Field(complexType, name, offset, GenUtils.fullyQualifiedName(schema, messageNameCamel, fieldName)));
    }

    private static SimpleType enumSimpleType(final PrimitiveType primitiveType)
    {
        final SimpleType simpleType;
        if (primitiveType == PrimitiveType.CHAR)
        {
            // Weird but we can't use char because wireshark has strange behaviour for this and we can't use string since strings don't work with representation tables
            simpleType = SimpleType.UINT8;
        }
        else
        {
            simpleType = simpleType(primitiveType);
        }
        return simpleType;
    }

    private static void parseEncodedDataType(
            final String schema, final String messageNameCamel,
            final EncodedDataType encodedDataType,
            final String name,
            final int offset,
            final FieldBundle fieldBundle
    )
    {
        final PrimitiveType primitiveType = encodedDataType.primitiveType();
        final SimpleType simpleType = simpleType(primitiveType);
        final String fieldName = GenUtils.camelCase(name);
        if (encodedDataType.presence() == Presence.CONSTANT)
        {
            fieldBundle.addField(new Field(new Constant(simpleType, primitiveValue(encodedDataType)), name, offset, GenUtils.fullyQualifiedName(schema, messageNameCamel, fieldName)));
        }
        else if (simpleType != SimpleType.STRING && encodedDataType.length() > 1)
        {
            fieldBundle.addField(new Field(new PrimitiveArray(simpleType, offset, encodedDataType.length()), name, offset, GenUtils.fullyQualifiedName(schema, messageNameCamel, fieldName)));
        }
        else if (encodedDataType.length() > 1)
        {
            fieldBundle.addField(new Field(new CharacterArray(simpleType, offset, encodedDataType.length()), name, offset, GenUtils.fullyQualifiedName(schema, messageNameCamel, fieldName)));
        }
        else
        {
            fieldBundle.addField(new Field(simpleType, name, offset, GenUtils.fullyQualifiedName(schema, messageNameCamel, fieldName)));
        }
    }

    private static String primitiveValue(final EncodedDataType encodedDataType)
    {
        return encodedDataType.constVal().toString();
    }

    private static void parseComposite(
            final String schema,
            final CompositeType encodedDataType,
            final String messageNameCamel,
            final String name,
            final int offset,
            final boolean isVariableLength,
            final FieldBundle fieldBundle
    )
    {
        final List<Type> typeList = encodedDataType.getTypeList();
        if (isVariableLengthData(isVariableLength, typeList))
        {
            final EncodedDataType lengthType = (EncodedDataType)typeList.get(0);
            final EncodedDataType type = (EncodedDataType)typeList.get(1);
            final String encoding = type.characterEncoding();
            final Base base;
            if (encoding == null)
            {
                throw new IllegalStateException("No encoding type set: " + type);
            }
            else if (encoding.contains("ASCII"))
            {
                base = Base.ASCII;
            }
            else if (encoding.contains("UTF"))
            {
                base = Base.UNICODE;
            }
            else
            {
                throw new IllegalStateException("Could not decode as character encoding is not recognised: " + type);
            }
            fieldBundle.addField(new Field(new VariableLengthData(simpleType(lengthType.primitiveType()), base), name, offset, GenUtils.fullyQualifiedName(schema, messageNameCamel, name)));
        }
        else
        {
            final Composite composite = buildComposite(schema, messageNameCamel, name, typeList, encodedDataType.encodedLength());
            fieldBundle.addField(new Field(composite, name, offset, GenUtils.fullyQualifiedName(schema, messageNameCamel, name)));
        }
    }

    private static Composite buildComposite(final String schema, final String messageNameCamel, final String name, final List<Type> typeList, final int encodedLength)
    {
        final Composite composite = new Composite(encodedLength);
        for (final Type type : typeList)
        {
            parseField(
                    schema,
                    messageNameCamel + "_" + GenUtils.camelCase(name),
                    type,
                    type.name(),
                    0,
                    type.isVariableLength(),
                    null,
                    composite
            );
        }
        return composite;
    }

    private static boolean isVariableLengthData(final boolean isVariableLength, final List<Type> typeList)
    {
        return isVariableLength && typeList.size() == 2 && typeList.get(1).encodedLength() == Token.VARIABLE_LENGTH && typeList.get(1) instanceof EncodedDataType;
    }

    @SuppressWarnings("ReturnCount")
    private static SimpleType simpleType(final PrimitiveType primitiveType)
    {
        switch (primitiveType)
        {
            case CHAR:
                return SimpleType.STRING;
            case INT8:
                return SimpleType.INT8;
            case INT16:
                return SimpleType.INT16;
            case INT32:
                return SimpleType.INT32;
            case INT64:
                return SimpleType.INT64;
            case UINT8:
                return SimpleType.UINT8;
            case UINT16:
                return SimpleType.UINT16;
            case UINT32:
                return SimpleType.UINT32;
            case UINT64:
                return SimpleType.UINT64;
            case FLOAT:
                return SimpleType.FLOAT;
            case DOUBLE:
                return SimpleType.DOUBLE;
        }
        throw new IllegalArgumentException("Could not cast: " + primitiveType);
    }

    private static final class Pair<L, R>
    {
        final L left;
        final R right;

        private Pair(final L left, final R right)
        {
            this.left = left;
            this.right = right;
        }
    }


}

package com.transficc.wiresharktools;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import com.transficc.wiresharktools.generator.Frame;
import com.transficc.wiresharktools.generator.SbeLuaGenerator;
import com.transficc.wiresharktools.generator.Schema;
import com.transficc.wiresharktools.generator.schemaparsing.SimpleType;
import com.transficc.wiresharktools.pcap.PcapFile;
import com.transficc.wiresharktools.testschema.protocol.Char20FieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.CharFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.ChoiceFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.CompositeFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.CompositeFieldWithEnumEncoder;
import com.transficc.wiresharktools.testschema.protocol.ConstantFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.ConstantStringFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.DoubleFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.EnumCharEncoder;
import com.transficc.wiresharktools.testschema.protocol.EnumCharField;
import com.transficc.wiresharktools.testschema.protocol.EnumConstantField;
import com.transficc.wiresharktools.testschema.protocol.EnumConstantFieldDecoder;
import com.transficc.wiresharktools.testschema.protocol.EnumConstantFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.EnumField;
import com.transficc.wiresharktools.testschema.protocol.EnumFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.FloatFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.GroupFieldMessageEncoder;
import com.transficc.wiresharktools.testschema.protocol.GroupFieldMessageWithOffsetsEncoder;
import com.transficc.wiresharktools.testschema.protocol.Int16FieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.Int32ArrayFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.Int32FieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.Int64FieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.Int8FieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.MessageEnvelopeEncoder;
import com.transficc.wiresharktools.testschema.protocol.MessageHeaderEncoder;
import com.transficc.wiresharktools.testschema.protocol.MoarChoiceFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.NewMessageFixedLengthFieldAddedEncoder;
import com.transficc.wiresharktools.testschema.protocol.NewMessageFixedLengthFieldAddedInGroupEncoder;
import com.transficc.wiresharktools.testschema.protocol.NewMessageVariableLengthFieldAddedEncoder;
import com.transficc.wiresharktools.testschema.protocol.NotAllowedWordMessageEncoder;
import com.transficc.wiresharktools.testschema.protocol.OffsetFieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.OldMessageEncoder;
import com.transficc.wiresharktools.testschema.protocol.SampleMessageEncoder;
import com.transficc.wiresharktools.testschema.protocol.Uint16FieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.Uint32FieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.Uint64FieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.Uint8FieldEncoder;
import com.transficc.wiresharktools.testschema.protocol.VarStringFieldEncoder;
import com.transficc.wiresharktools.testschema.subprotocol.DuplicateAcrossSchemasEncoder;
import com.transficc.wiresharktools.testschema.subprotocol.SubProtocolGroupFieldMessageEncoder;
import com.transficc.wiresharktools.testschema.subprotocol.SubProtocolMessageEncoder;

import org.agrona.ExpandableArrayBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.sbe.MessageFlyweight;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import static org.assertj.core.api.Assertions.assertThat;


import uk.co.real_logic.sbe.xml.MessageSchema;
import uk.co.real_logic.sbe.xml.ParserOptions;
import uk.co.real_logic.sbe.xml.XmlSchemaParser;


@Timeout(5)
public class CaptureIntegrationTest
{
    private static final int PROTOCOL_DEST_PORT = 30102;
    private static final int LENGTH_FIELD_DEST_PORT = 10101;
    private static final boolean SHOULD_DUMP = false;
    private static final String PROTOCOL_PRETTY_NAME = "MyClient";
    private static final String PROTOCOL = PROTOCOL_PRETTY_NAME.toLowerCase();
    private static final char CHAR_FIELD = 'c';
    private static final char OFFSET_FIELD = 'd';
    private static final String CHAR_20_FIELD = "char20Field";
    private static final byte INT_8_FIELD = (byte)21;
    private static final short INT_16_FIELD = (short)22;
    private static final int INT_32_FIELD = 23;
    private static final int INT_64_FIELD = 24;
    private static final short UINT_8_FIELD = (short)25;
    private static final int UINT_16_FIELD = 26;
    private static final int UINT_32_FIELD = 27;
    private static final int UINT_64_FIELD = 28;
    private static final float FLOAT_FIELD = (float)29.1;
    private static final double DOUBLE_FIELD = 30.2;
    private static final byte COMPOSITE_FIELD_1 = 34;
    private static final int COMPOSITE_FIELD_2 = 35;
    private static final EnumField ENUM_FIELD = EnumField.OPTION1;
    private static final boolean BACON = true;
    private static final boolean LETTUCE = false;
    private static final boolean TOMATO = true;
    private static final int GROUP_FIXED_LENGTH_FIELD_1 = 36;
    private static final String GROUP_VARIABLE_LENGTH_FIELD_1 = "37";
    private static final int GROUP_FIXED_LENGTH_FIELD_2 = 38;
    private static final String GROUP_VARIABLE_LENGTH_FIELD_2 = "39";
    private static final int SUB_GROUP_FIX_LENGTH_FIELD_1 = 10101;
    private static final int SUB_GROUP_FIX_LENGTH_FIELD_2 = 20202;
    private static final int SUB_GROUP_FIX_LENGTH_FIELD_3 = 30303;
    private static final String SUB_GROUP_VAR_LENGTH_FIELD_1 = "SUB_GROUP_FIELD_1";
    private static final String SUB_GROUP_VAR_LENGTH_FIELD_2 = "SUB_GROUP_FIELD_2";
    private static final String SUB_GROUP_VAR_LENGTH_FIELD_3 = "SUB_GROUP_FIELD_3";
    private static final String VAR_STRING_FIELD = "VAR_STRING_FIELD";
    private static final char ENVELOPE_CHAR_FIELD = 'B';
    private static final String SUB_COMPOSITE_FIELD = "BOB";
    private static final int[] INT_32_ARRAY_FIELD = new int[]{31, 32, 33, 0, 0, 0, 0, 0, 0, 0};
    private final MessageHeaderEncoder sampleHeaderEncoder = new MessageHeaderEncoder();
    private final com.transficc.wiresharktools.testschema.subprotocol.MessageHeaderEncoder subProtocolHeaderEncoder = new com.transficc.wiresharktools.testschema.subprotocol.MessageHeaderEncoder();
    private final com.transficc.wiresharktools.testschema.subprotocol.MessageHeaderEncoder clobHeaderEncoder = new com.transficc.wiresharktools.testschema.subprotocol.MessageHeaderEncoder();
    private final SampleMessageEncoder sampleMessageEncoder = new SampleMessageEncoder();
    private final MessageEnvelopeEncoder messageEnvelopeEncoder = new MessageEnvelopeEncoder();
    private final SubProtocolMessageEncoder subProtocolMessageEncoder = new SubProtocolMessageEncoder();
    @SuppressWarnings("SystemOut")
    private final PrintStream dumpOutput = System.out;

    public static MessageSchema readSchemaFromClassPath(final String schemaLocation)
    {
        try
        {
            final InputStream schema = SbeLuaGenerator.class.getResourceAsStream(schemaLocation);
            return XmlSchemaParser.parse(schema, ParserOptions.DEFAULT);
        }
        catch (final Exception e)
        {
            throw new IllegalStateException("Could not parse schema: " + schemaLocation, e);
        }
    }

    public static MessageSchema readSchemaFromPath(final Path schemaLocation)
    {
        try
        {
            final FileInputStream schema = new FileInputStream(schemaLocation.toFile());
            return XmlSchemaParser.parse(schema, ParserOptions.DEFAULT);
        }
        catch (final Exception e)
        {
            throw new IllegalStateException("Could not parse schema: " + schemaLocation, e);
        }
    }

    @Test
    void shouldCaptureAndReadMultipleMessages()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final byte[] firstMessage = "Hello world!".getBytes(StandardCharsets.US_ASCII);
        final byte[] secondMessage = "Goodbye universe!".getBytes(StandardCharsets.US_ASCII);

        final byte[] toWrite = writeToPcapFormat(LENGTH_FIELD_DEST_PORT, setUp, firstMessage, secondMessage);
        final String documentContext = pcapToXml(toWrite, luaScript);
        assertThat(readFromXpath(documentContext, "//packet[1]/proto[@name=\"fake-field-wrapper\"]/field[@name=\"data\"]/field[@name=\"data.text\"]/@show")).isEqualTo("Hello world!");
        assertThat(readFromXpath(documentContext, "//packet[2]/proto[@name=\"fake-field-wrapper\"]/field[@name=\"data\"]/field[@name=\"data.text\"]/@show")).isEqualTo("Goodbye universe!");
    }

    @Test
    void shouldDecodeMessageSplitAcrossPackets()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Char20FieldEncoder encoder = new Char20FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).char20Field(CHAR_20_FIELD), setUp.frame());
        final byte[] firstHalf = Arrays.copyOfRange(message, 0, message.length / 2);
        final byte[] secondHalf = Arrays.copyOfRange(message, message.length / 2, message.length);
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, firstHalf, secondHalf);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "char20Field"))).isEqualTo("" + CHAR_20_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeMultipleMessagesInPacket()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Char20FieldEncoder encoder = new Char20FieldEncoder();
        final byte[] message1 = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).char20Field("first"), setUp.frame());
        final byte[] message2 = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).char20Field("second"), setUp.frame());
        final byte[] twoMessages = new byte[message1.length + message2.length];
        System.arraycopy(message1, 0, twoMessages, 0, message1.length);
        System.arraycopy(message2, 0, twoMessages, message1.length, message2.length);
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, twoMessages);

        final String xml = pcapToXml(toWrite, luaScript);
        assertThat(readFromXpath(xml, fieldByName("show", "char20Field"), 0)).isEqualTo("first");
        assertThat(readFromXpath(xml, fieldByName("show", "char20Field"), 1)).isEqualTo("second");
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeMessagesSplitAcrossMultiplePackets()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Char20FieldEncoder encoder = new Char20FieldEncoder();
        final byte[] message1 = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).char20Field("first"), setUp.frame());
        final byte[] message2 = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).char20Field("second"), setUp.frame());
        final byte[] message3 = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).char20Field("third"), setUp.frame());

        final byte[] packet1 = new byte[message1.length + (message2.length / 2)];
        final byte[] packet2 = new byte[message3.length + (message2.length - (message2.length / 2))];

        System.arraycopy(message1, 0, packet1, 0, message1.length);
        System.arraycopy(message2, 0, packet1, message1.length, message2.length / 2);

        System.arraycopy(message2, message2.length / 2, packet2, 0, (message2.length - (message2.length / 2)));
        System.arraycopy(message3, 0, packet2, (message2.length - (message2.length / 2)), message3.length);


        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, packet1, packet2);
        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "char20Field"), 0)).isEqualTo("first");
        assertThat(readFromXpath(xml, fieldByName("show", "char20Field"), 1)).isEqualTo("second");
        assertThat(readFromXpath(xml, fieldByName("show", "char20Field"), 2)).isEqualTo("third");
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeMessageSplitAcrossPacketsWithLessThanFrameInFirst()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Char20FieldEncoder encoder = new Char20FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).char20Field(CHAR_20_FIELD), setUp.frame());
        final byte[] firstHalf = Arrays.copyOfRange(message, 0, 5);
        final byte[] secondHalf = Arrays.copyOfRange(message, 5, message.length);
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, firstHalf, secondHalf);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "char20Field"))).isEqualTo("" + CHAR_20_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeSubProtocol()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final byte[] firstMessage = subProtocolMessage(setUp.frame());

        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, firstMessage);

        final String documentContext = pcapToXml(toWrite, luaScript);
        {
            final String int64Field = readFromXpath(documentContext, envelopedMessagePath() + "/field[@name=\"int64Field\"]/@show");
            assertThat(int64Field).isEqualTo("" + INT_64_FIELD);
        }
    }

    @Test
    void shouldDecodeFrameWithInclusiveLength()
    {
        final SetUp setUp = SetUp.createSetUp().withFrame(new Frame(SimpleType.INT32, 5, 3, true));
        final File luaScript = setUp.buildDissector();
        final Char20FieldEncoder encoder = new Char20FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).char20Field(CHAR_20_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "char20Field"))).isEqualTo("" + CHAR_20_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeCharField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final CharFieldEncoder encoder = new CharFieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).charField((byte)CHAR_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "charField"))).isEqualTo("" + CHAR_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeOffsetField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final OffsetFieldEncoder encoder = new OffsetFieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).offsetField((byte)OFFSET_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "offsetField"))).isEqualTo("" + OFFSET_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeChar20Field()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Char20FieldEncoder encoder = new Char20FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).char20Field(CHAR_20_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "char20Field"))).isEqualTo("" + CHAR_20_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeInt8Field()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Int8FieldEncoder encoder = new Int8FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).int8Field(INT_8_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "int8Field"))).isEqualTo("" + INT_8_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeEnumField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final EnumFieldEncoder encoder = new EnumFieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).enumField(ENUM_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("showname", "enumField"))).isEqualTo(enumFieldRepr(ENUM_FIELD));
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeEnumCharField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final EnumCharEncoder encoder = new EnumCharEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).enumCharField(EnumCharField.char1), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("showname", "enumCharField"))).isEqualTo(enumFieldRepr(EnumCharField.char1));
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeInt16Field()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Int16FieldEncoder encoder = new Int16FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).int16Field(INT_16_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "int16Field"))).isEqualTo("" + INT_16_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeInt32Field()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Int32FieldEncoder encoder = new Int32FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).int32Field(INT_32_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "int32Field"))).isEqualTo("" + INT_32_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeInt64Field()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Int64FieldEncoder encoder = new Int64FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).int64Field(INT_64_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "int64Field"))).isEqualTo("" + INT_64_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeUint8Field()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Uint8FieldEncoder encoder = new Uint8FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).uint8Field(UINT_8_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "uint8Field"))).isEqualTo("" + UINT_8_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeUint16Field()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Uint16FieldEncoder encoder = new Uint16FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).uint16Field(UINT_16_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "uint16Field"))).isEqualTo("" + UINT_16_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeUint32Field()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Uint32FieldEncoder encoder = new Uint32FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).uint32Field(UINT_32_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "uint32Field"))).isEqualTo("" + UINT_32_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeUint64Field()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Uint64FieldEncoder encoder = new Uint64FieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).uint64Field(UINT_64_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "uint64Field"))).isEqualTo("" + UINT_64_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeFloatField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final FloatFieldEncoder encoder = new FloatFieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).floatField(FLOAT_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "floatField"))).isEqualTo("" + FLOAT_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeDoubleField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final DoubleFieldEncoder encoder = new DoubleFieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).doubleField(DOUBLE_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "doubleField"))).isEqualTo("" + DOUBLE_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeDuplicateNamedMessagesAcrossSchemas()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final com.transficc.wiresharktools.testschema.protocol.DuplicateAcrossSchemasEncoder encoder1 = new com.transficc.wiresharktools.testschema.protocol.DuplicateAcrossSchemasEncoder();
        final DuplicateAcrossSchemasEncoder encoder2 = new DuplicateAcrossSchemasEncoder();
        final byte[] message1 = writeMessage(encoder1, (buffer, offset) -> encoder1.wrap(buffer, offset).duplicateFieldAcrossSchemas(INT_32_FIELD), setUp.frame());
        final byte[] message2 = writeSubProtocolMessage(encoder2, (buffer, offset) -> encoder2.wrap(buffer, offset).duplicateFieldAcrossSchemas((byte)CHAR_FIELD), setUp.frame());
        final byte[] toWrite1 = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message1);
        final byte[] toWrite2 = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message2);

        final String xml1 = pcapToXml(toWrite1, luaScript);
        final String xml2 = pcapToXml(toWrite2, luaScript);
        assertThat(readFromXpath(xml1, fieldByName("show", "duplicateFieldAcrossSchemas"))).isEqualTo("" + INT_32_FIELD);
        assertThat(readFromXpath(xml2, fieldByName("show", "duplicateFieldAcrossSchemas"))).isEqualTo("" + CHAR_FIELD);
        assertThat(xml1).doesNotContain("Lua Error: ");
        assertThat(xml2).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeInt32ArrayField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final Int32ArrayFieldEncoder encoder = new Int32ArrayFieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) ->
        {
            encoder.wrap(buffer, offset);
            for (int i = 0; i < INT_32_ARRAY_FIELD.length; i++)
            {
                encoder.int32ArrayField(i, INT_32_ARRAY_FIELD[i]);
            }
        }, setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[0]"))).isEqualTo("" + INT_32_ARRAY_FIELD[0]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[1]"))).isEqualTo("" + INT_32_ARRAY_FIELD[1]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[2]"))).isEqualTo("" + INT_32_ARRAY_FIELD[2]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[3]"))).isEqualTo("" + INT_32_ARRAY_FIELD[3]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[4]"))).isEqualTo("" + INT_32_ARRAY_FIELD[4]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[5]"))).isEqualTo("" + INT_32_ARRAY_FIELD[5]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[6]"))).isEqualTo("" + INT_32_ARRAY_FIELD[6]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[7]"))).isEqualTo("" + INT_32_ARRAY_FIELD[7]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[8]"))).isEqualTo("" + INT_32_ARRAY_FIELD[8]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[9]"))).isEqualTo("" + INT_32_ARRAY_FIELD[9]);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeCompositeField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final CompositeFieldEncoder encoder = new CompositeFieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder
                .wrap(buffer, offset)
                .compositeField()
                .compositeField1(COMPOSITE_FIELD_1)
                .compositeField2(COMPOSITE_FIELD_2)
                .subComposite()
                .subCompositeField1(SUB_COMPOSITE_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);
        assertThat(
                readFromXpath(
                        xml,
                        fieldByName("pos", "compositeField")
                )
        )
                .describedAs("Ensure buffer graphic in wireshark displays the correct position in the stream of the composite")
                .isEqualTo("" + 86);
        assertThat(readFromXpath(xml, fieldByName("size", "compositeField")))
                .describedAs("Ensure buffer graphic in wireshark displays the correct size in the stream of the composite")
                .isEqualTo("" + 8);
        assertThat(readFromXpath(xml, fieldByName("show", "compositeField", "compositeField1"))).isEqualTo("" + COMPOSITE_FIELD_1);
        assertThat(readFromXpath(xml, fieldByName("show", "compositeField", "compositeField2"))).isEqualTo("" + COMPOSITE_FIELD_2);
        assertThat(readFromXpath(xml, fieldByName("show", "compositeField", "subComposite", "subCompositeField1"))).isEqualTo("" + SUB_COMPOSITE_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeChoiceField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final ChoiceFieldEncoder encoder = new ChoiceFieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).choiceField().tomato(TOMATO).bacon(BACON).lettuce(LETTUCE), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("showname", "choiceField", "bacon"))).contains(booleanRepr("bacon", BACON));
        assertThat(readFromXpath(xml, fieldByName("showname", "choiceField", "lettuce"))).contains(booleanRepr("lettuce", LETTUCE));
        assertThat(readFromXpath(xml, fieldByName("showname", "choiceField", "tomato"))).contains(booleanRepr("tomato", TOMATO));
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeGroupField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final GroupFieldMessageEncoder encoder = new GroupFieldMessageEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) ->
        {
            encoder.wrap(buffer, offset);
            final GroupFieldMessageEncoder.GroupFieldEncoder groupField = encoder
                    .int32Field(42)
                    .groupFieldCount(2);
            groupField
                    .next()
                    .groupFixedLengthField(GROUP_FIXED_LENGTH_FIELD_1);

            final GroupFieldMessageEncoder.GroupFieldEncoder.SubGroupFieldEncoder subGroup1Encoder = groupField
                    .subGroupFieldCount(2);
            subGroup1Encoder
                    .next()
                    .subGroupFixedLengthField(SUB_GROUP_FIX_LENGTH_FIELD_1)
                    .subGroupVariableLengthField(SUB_GROUP_VAR_LENGTH_FIELD_1)
                    .next()
                    .subGroupFixedLengthField(SUB_GROUP_FIX_LENGTH_FIELD_2)
                    .subGroupVariableLengthField(SUB_GROUP_VAR_LENGTH_FIELD_2);

            groupField
                    .groupVariableLengthField(GROUP_VARIABLE_LENGTH_FIELD_1);

            groupField
                    .next()
                    .groupFixedLengthField(GROUP_FIXED_LENGTH_FIELD_2);

            final GroupFieldMessageEncoder.GroupFieldEncoder.SubGroupFieldEncoder subGroup2Encoder = groupField
                    .subGroupFieldCount(1)
                    .next();
            subGroup2Encoder
                    .subGroupFixedLengthField(SUB_GROUP_FIX_LENGTH_FIELD_3)
                    .subGroupVariableLengthField(SUB_GROUP_VAR_LENGTH_FIELD_3);

            groupField
                    .groupVariableLengthField(GROUP_VARIABLE_LENGTH_FIELD_2);
        }, setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "int32Field"))).isEqualTo("42");
        assertThat(readFromXpath(xml, fieldByShowName("groupField[0]") + "/field[@name=\"groupFixedLengthField\"]/@show")).isEqualTo("" + GROUP_FIXED_LENGTH_FIELD_1);
        assertThat(readFromXpath(xml, fieldByShowName("groupField[0]") + "/field[@name=\"groupVariableLengthField\"]/@show")).isEqualTo("" + GROUP_VARIABLE_LENGTH_FIELD_1);
        assertThat(readFromXpath(xml, subGroup(0, 0) + "/field[@name=\"subGroupFixedLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_FIX_LENGTH_FIELD_1);
        assertThat(readFromXpath(xml, subGroup(0, 0) + "/field[@name=\"subGroupVariableLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_VAR_LENGTH_FIELD_1);
        assertThat(readFromXpath(xml, subGroup(0, 1) + "/field[@name=\"subGroupFixedLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_FIX_LENGTH_FIELD_2);
        assertThat(readFromXpath(xml, subGroup(0, 1) + "/field[@name=\"subGroupVariableLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_VAR_LENGTH_FIELD_2);
        assertThat(readFromXpath(xml, fieldByShowName("groupField[1]") + "/field[@name=\"groupFixedLengthField\"]/@show")).isEqualTo("" + GROUP_FIXED_LENGTH_FIELD_2);
        assertThat(readFromXpath(xml, fieldByShowName("groupField[1]") + "/field[@name=\"groupVariableLengthField\"]/@show")).isEqualTo("" + GROUP_VARIABLE_LENGTH_FIELD_2);
        assertThat(readFromXpath(xml, subGroup(1, 0) + "/field[@name=\"subGroupFixedLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_FIX_LENGTH_FIELD_3);
        assertThat(readFromXpath(xml, subGroup(1, 0) + "/field[@name=\"subGroupVariableLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_VAR_LENGTH_FIELD_3);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeOffsetsWithinGroupField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final GroupFieldMessageWithOffsetsEncoder encoder = new GroupFieldMessageWithOffsetsEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) ->
        {
            encoder.wrap(buffer, offset);
            final GroupFieldMessageWithOffsetsEncoder.GroupFieldEncoder groupField = encoder
                    .int32Field(42)
                    .groupFieldCount(2);
            groupField
                    .next()
                    .groupOffsetField((byte)'c');
            for (int i = 0; i < INT_32_ARRAY_FIELD.length; i++)
            {
                groupField.groupInt32ArrayField(i, INT_32_ARRAY_FIELD[i]);
            }

            groupField
                    .next()
                    .groupOffsetField((byte)'d');
            for (int i = 0; i < INT_32_ARRAY_FIELD.length; i++)
            {
                groupField.groupInt32ArrayField(i, INT_32_ARRAY_FIELD[i] + INT_32_ARRAY_FIELD.length);
            }

        }, setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);
        assertThat(readFromXpath(xml, fieldByShowName("groupField[0]") + "/field[@name=\"groupOffsetField\"]/@show")).isEqualTo("c");
        for (int i = 0; i < INT_32_ARRAY_FIELD.length; i++)
        {
            assertThat(readFromXpath(xml, fieldByShowName("groupField[0]") + "/field[@showname=\"groupInt32ArrayField[" + i + "]\"]/@show")).isEqualTo("" + INT_32_ARRAY_FIELD[i]);
        }
        assertThat(readFromXpath(xml, fieldByShowName("groupField[1]") + "/field[@name=\"groupOffsetField\"]/@show")).isEqualTo("d");
        for (int i = 0; i < INT_32_ARRAY_FIELD.length; i++)
        {
            assertThat(readFromXpath(xml, fieldByShowName("groupField[1]") + "/field[@showname=\"groupInt32ArrayField[" + i + "]\"]/@show")).isEqualTo("" + (
                    INT_32_ARRAY_FIELD[i]
                    + INT_32_ARRAY_FIELD.length
            ));
        }
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeVarStringField()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final VarStringFieldEncoder encoder = new VarStringFieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).varStringField(VAR_STRING_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "varStringField"))).isEqualTo(VAR_STRING_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldHandleNotAllowedSpecialWordsInAbbreviations()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final NotAllowedWordMessageEncoder encoder = new NotAllowedWordMessageEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).text(VAR_STRING_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "field_text"))).isEqualTo(VAR_STRING_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void shouldDecodeAllDataTypes()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final byte[] firstMessage = sampleMessage(setUp.frame());

        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, firstMessage);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "charField"))).isEqualTo("" + CHAR_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "offsetField"))).isEqualTo("" + OFFSET_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "char20Field"))).isEqualTo(CHAR_20_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "int8Field"))).isEqualTo("" + INT_8_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "int16Field"))).isEqualTo("" + INT_16_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "int32Field"))).isEqualTo("" + INT_32_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "int64Field"))).isEqualTo("" + INT_64_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "uint8Field"))).isEqualTo("" + UINT_8_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "uint16Field"))).isEqualTo("" + UINT_16_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "uint32Field"))).isEqualTo("" + UINT_32_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "uint64Field"))).isEqualTo("" + UINT_64_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "floatField"))).isEqualTo("" + FLOAT_FIELD);
        assertThat(readFromXpath(xml, fieldByName("show", "doubleField"))).isEqualTo("" + DOUBLE_FIELD);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[0]"))).isEqualTo("" + INT_32_ARRAY_FIELD[0]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[1]"))).isEqualTo("" + INT_32_ARRAY_FIELD[1]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[2]"))).isEqualTo("" + INT_32_ARRAY_FIELD[2]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[3]"))).isEqualTo("" + INT_32_ARRAY_FIELD[3]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[4]"))).isEqualTo("" + INT_32_ARRAY_FIELD[4]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[5]"))).isEqualTo("" + INT_32_ARRAY_FIELD[5]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[6]"))).isEqualTo("" + INT_32_ARRAY_FIELD[6]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[7]"))).isEqualTo("" + INT_32_ARRAY_FIELD[7]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[8]"))).isEqualTo("" + INT_32_ARRAY_FIELD[8]);
        assertThat(readFromXpath(xml, fieldByShowName("show", "int32ArrayField[9]"))).isEqualTo("" + INT_32_ARRAY_FIELD[9]);
        assertThat(readFromXpath(xml, fieldByName("show", "compositeField", "compositeField1"))).isEqualTo("" + COMPOSITE_FIELD_1);
        assertThat(readFromXpath(xml, fieldByName("show", "compositeField", "compositeField2"))).isEqualTo("" + COMPOSITE_FIELD_2);
        assertThat(readFromXpath(xml, fieldByName("show", "compositeField", "subComposite", "subCompositeField1"))).isEqualTo("" + SUB_COMPOSITE_FIELD);
        assertThat(readFromXpath(xml, fieldByName("showname", "enumField"))).isEqualTo("enumField: " + ENUM_FIELD.name() + " (" + ENUM_FIELD.value() + ")");
        assertThat(readFromXpath(xml, fieldByName("showname", "choiceField", "bacon"))).contains(booleanRepr("bacon", BACON));
        assertThat(readFromXpath(xml, fieldByName("showname", "choiceField", "lettuce"))).contains(booleanRepr("lettuce", LETTUCE));
        assertThat(readFromXpath(xml, fieldByName("showname", "choiceField", "tomato"))).contains(booleanRepr("tomato", TOMATO));
        assertThat(readFromXpath(xml, fieldByShowName("groupField[0]") + "/field[@name=\"groupFixedLengthField\"]/@show")).isEqualTo("" + GROUP_FIXED_LENGTH_FIELD_1);
        assertThat(readFromXpath(xml, fieldByShowName("groupField[0]") + "/field[@name=\"groupVariableLengthField\"]/@show")).isEqualTo("" + GROUP_VARIABLE_LENGTH_FIELD_1);
        assertThat(readFromXpath(xml, subGroup(0, 0) + "/field[@name=\"subGroupFixedLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_FIX_LENGTH_FIELD_1);
        assertThat(readFromXpath(xml, subGroup(0, 0) + "/field[@name=\"subGroupVariableLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_VAR_LENGTH_FIELD_1);
        assertThat(readFromXpath(xml, subGroup(0, 1) + "/field[@name=\"subGroupFixedLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_FIX_LENGTH_FIELD_2);
        assertThat(readFromXpath(xml, subGroup(0, 1) + "/field[@name=\"subGroupVariableLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_VAR_LENGTH_FIELD_2);
        assertThat(readFromXpath(xml, fieldByShowName("groupField[1]") + "/field[@name=\"groupFixedLengthField\"]/@show")).isEqualTo("" + GROUP_FIXED_LENGTH_FIELD_2);
        assertThat(readFromXpath(xml, fieldByShowName("groupField[1]") + "/field[@name=\"groupVariableLengthField\"]/@show")).isEqualTo("" + GROUP_VARIABLE_LENGTH_FIELD_2);
        assertThat(readFromXpath(xml, subGroup(1, 0) + "/field[@name=\"subGroupFixedLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_FIX_LENGTH_FIELD_3);
        assertThat(readFromXpath(xml, subGroup(1, 0) + "/field[@name=\"subGroupVariableLengthField\"]/@show")).isEqualTo("" + SUB_GROUP_VAR_LENGTH_FIELD_3);
        assertThat(readFromXpath(xml, fieldByName("show", "varStringField"))).isEqualTo(VAR_STRING_FIELD);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void testConstantFields()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final ConstantFieldEncoder encoder = new ConstantFieldEncoder();
        final byte[] message = writeMessage(encoder, encoder::wrap, setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "constantField"))).isEqualTo("" + encoder.constantField());
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void testConstantStringFields()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final ConstantStringFieldEncoder encoder = new ConstantStringFieldEncoder();
        final byte[] message = writeMessage(encoder, encoder::wrap, setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "constantStringField"))).isEqualTo("" + encoder.constantStringField());
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void testCompositeWithEnum()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final CompositeFieldWithEnumEncoder encoder = new CompositeFieldWithEnumEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).compositeFieldWithEnum().enumField(ENUM_FIELD), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("showname", "compositeFieldWithEnum", "enumField"))).isEqualTo(enumFieldRepr(ENUM_FIELD));
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void testConstantEnumFields()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final EnumConstantFieldEncoder encoder = new EnumConstantFieldEncoder();
        final byte[] message = writeMessage(encoder, encoder::wrap, setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        final EnumConstantField enumField = new EnumConstantFieldDecoder().enumConstantField();
        assertThat(readFromXpath(xml, fieldByName("showname", "enumConstantField"))).isEqualTo("enumConstantField: " + enumField + " (" + enumField.value() + ")");
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void testDifferentLengthSet()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final MoarChoiceFieldEncoder encoder = new MoarChoiceFieldEncoder();
        final byte[] message = writeMessage(encoder, (buffer, offset) -> encoder.wrap(buffer, offset).moarChoiceField().moarTomato(TOMATO).moarBacon(BACON).moarLettuce(LETTUCE), setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("showname", "moarChoiceField", "moarBacon"))).contains(booleanRepr("moarBacon", BACON));
        assertThat(readFromXpath(xml, fieldByName("showname", "moarChoiceField", "moarLettuce"))).contains(booleanRepr("moarLettuce", LETTUCE));
        assertThat(readFromXpath(xml, fieldByName("showname", "moarChoiceField", "moarTomato"))).contains(booleanRepr("moarTomato", TOMATO));
        assertThat(xml).doesNotContain("Lua Error: ");

    }

    @Test
    void testOverridenGroupDimensionType()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final SubProtocolGroupFieldMessageEncoder encoder = new SubProtocolGroupFieldMessageEncoder();
        final byte[] message = writeSubProtocolMessage(encoder, (buffer, offset) ->
        {
            encoder.wrap(buffer, offset);
            final SubProtocolGroupFieldMessageEncoder.GroupFieldEncoder groupField = encoder
                    .groupFieldCount(2);
            groupField
                    .next()
                    .groupFixedLengthField(GROUP_FIXED_LENGTH_FIELD_1)
                    .next()
                    .groupFixedLengthField(GROUP_FIXED_LENGTH_FIELD_2);
        }, setUp.frame());
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, message);

        final String xml = pcapToXml(toWrite, luaScript);

        final String path1 = messagePath() + "/field[@showname=\"groupField[0]\"]/field[@name=\"groupFixedLengthField\"]/@show";
        final String path2 = messagePath() + "/field[@showname=\"groupField[1]\"]/field[@name=\"groupFixedLengthField\"]/@show";
        assertThat(readFromXpath(xml, path1)).isEqualTo("" + GROUP_FIXED_LENGTH_FIELD_1);
        assertThat(readFromXpath(xml, path2)).isEqualTo("" + GROUP_FIXED_LENGTH_FIELD_2);
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void testOverridenHeaderType()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final byte[] firstMessage = subProtocolMessage(setUp.frame());

        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, firstMessage);

        final String documentContext = pcapToXml(toWrite, luaScript);
        {
            final String int64Field = readFromXpath(documentContext, envelopedMessagePath() + "/field[@name=\"int64Field\"]/@show");
            assertThat(int64Field).isEqualTo("" + INT_64_FIELD);
        }
    }

    @Test
    void handleNewerUnknownFixedLengthFieldAtMessageLevel()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final NewMessageFixedLengthFieldAddedEncoder encoderNew = new NewMessageFixedLengthFieldAddedEncoder();
        final ExpandableArrayBuffer message1 = new ExpandableArrayBuffer();

        // Fake a newer SBE schema version and template ID to make it look like the old one
        sampleHeaderEncoder
                .wrap(message1, frameSize(setUp.frame()))
                .blockLength(encoderNew.sbeBlockLength())
                .templateId(OldMessageEncoder.TEMPLATE_ID)
                .schemaId(encoderNew.sbeSchemaId())
                .version(encoderNew.sbeSchemaVersion() + 1);

        final int offset = frameSize(setUp.frame()) + sampleHeaderEncoder.encodedLength();
        encoderNew.wrap(message1, offset)
                .int32Field1(1)
                .int32Field2(2)
                .groupField1Count(1)
                .next()
                .groupFixedLengthField1(100)
                .groupVariableLengthField1("101");
        encoderNew.variableLengthField1("1000");

        writeFrame(message1, sampleHeaderEncoder.encodedLength() + ((MessageFlyweight)encoderNew).encodedLength(), setUp.frame());
        final byte[] output = new byte[frameSize(setUp.frame()) + sampleHeaderEncoder.encodedLength() + ((MessageFlyweight)encoderNew).encodedLength()];
        message1.getBytes(0, output, 0, output.length);
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, output);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "int32Field1"))).isEqualTo("1");
        assertThat(readFromXpath(xml, fieldByShowName("groupField1[0]") + "/field[@name=\"groupFixedLengthField1\"]/@show")).isEqualTo("100");
        assertThat(readFromXpath(xml, fieldByShowName("groupField1[0]") + "/field[@name=\"groupVariableLengthField1\"]/@show")).isEqualTo("101");
        assertThat(readFromXpath(xml, fieldByName("show", "variableLengthField1"))).isEqualTo("1000");
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void handleNewerUnknownVariableLengthFieldAtMessageLevel()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final NewMessageVariableLengthFieldAddedEncoder encoderNew = new NewMessageVariableLengthFieldAddedEncoder();
        final ExpandableArrayBuffer message1 = new ExpandableArrayBuffer();

        // Fake a newer SBE schema version and template ID to make it look like the old one
        sampleHeaderEncoder
                .wrap(message1, frameSize(setUp.frame()))
                .blockLength(encoderNew.sbeBlockLength())
                .templateId(OldMessageEncoder.TEMPLATE_ID)
                .schemaId(encoderNew.sbeSchemaId())
                .version(encoderNew.sbeSchemaVersion() + 1);

        final int offset = frameSize(setUp.frame()) + sampleHeaderEncoder.encodedLength();
        encoderNew.wrap(message1, offset)
                .int32Field1(1)
                .groupField1Count(1)
                .next()
                .groupFixedLengthField1(100)
                .groupVariableLengthField1("101");
        encoderNew.variableLengthField1("1000")
                .variableLengthField2("102");

        writeFrame(message1, sampleHeaderEncoder.encodedLength() + ((MessageFlyweight)encoderNew).encodedLength(), setUp.frame());
        final byte[] output = new byte[frameSize(setUp.frame()) + sampleHeaderEncoder.encodedLength() + ((MessageFlyweight)encoderNew).encodedLength()];
        message1.getBytes(0, output, 0, output.length);
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, output);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "int32Field1"))).isEqualTo("1");
        assertThat(readFromXpath(xml, fieldByShowName("groupField1[0]") + "/field[@name=\"groupFixedLengthField1\"]/@show")).isEqualTo("100");
        assertThat(readFromXpath(xml, fieldByShowName("groupField1[0]") + "/field[@name=\"groupVariableLengthField1\"]/@show")).isEqualTo("101");
        assertThat(readFromXpath(xml, fieldByName("show", "variableLengthField1"))).isEqualTo("1000");
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    @Test
    void handleNewerUnknownFixedLengthFieldAtGroupLevel()
    {
        final SetUp setUp = SetUp.createSetUp();
        final File luaScript = setUp.buildDissector();
        final NewMessageFixedLengthFieldAddedInGroupEncoder encoderNew = new NewMessageFixedLengthFieldAddedInGroupEncoder();
        final ExpandableArrayBuffer message1 = new ExpandableArrayBuffer();

        // Fake a newer SBE schema version and template ID to make it look like the old one
        sampleHeaderEncoder
                .wrap(message1, frameSize(setUp.frame()))
                .blockLength(encoderNew.sbeBlockLength())
                .templateId(OldMessageEncoder.TEMPLATE_ID)
                .schemaId(encoderNew.sbeSchemaId())
                .version(encoderNew.sbeSchemaVersion() + 1);

        final int offset = frameSize(setUp.frame()) + sampleHeaderEncoder.encodedLength();
        encoderNew.wrap(message1, offset)
                .int32Field1(1)
                .groupField1Count(1)
                .next()
                .groupFixedLengthField1(100)
                .groupFixedLengthField2(200)
                .groupVariableLengthField1("101");
        encoderNew.variableLengthField1("1000");

        writeFrame(message1, sampleHeaderEncoder.encodedLength() + ((MessageFlyweight)encoderNew).encodedLength(), setUp.frame());
        final byte[] output = new byte[frameSize(setUp.frame()) + sampleHeaderEncoder.encodedLength() + ((MessageFlyweight)encoderNew).encodedLength()];
        message1.getBytes(0, output, 0, output.length);
        final byte[] toWrite = writeToPcapFormat(PROTOCOL_DEST_PORT, setUp, output);

        final String xml = pcapToXml(toWrite, luaScript);

        assertThat(readFromXpath(xml, fieldByName("show", "int32Field1"))).isEqualTo("1");
        assertThat(readFromXpath(xml, fieldByShowName("groupField1[0]") + "/field[@name=\"groupFixedLengthField1\"]/@show")).isEqualTo("100");
        assertThat(readFromXpath(xml, fieldByShowName("groupField1[0]") + "/field[@name=\"groupVariableLengthField1\"]/@show")).isEqualTo("101");
        assertThat(readFromXpath(xml, fieldByName("show", "variableLengthField1"))).isEqualTo("1000");
        assertThat(xml).doesNotContain("Lua Error: ");
    }

    private static String enumFieldRepr(final EnumField enumField)
    {
        return "enumField: " + enumField + " (" + enumField.value() + ")";
    }

    private static String enumFieldRepr(final EnumCharField enumField)
    {
        return "enumCharField: " + enumField + " (" + enumField.value() + ")";
    }

    private static String subGroup(final int group, final int subGroup)
    {
        return fieldByShowName("groupField[" + group + "]") + "/field[@showname=\"subGroupField[" + subGroup + "]\"]";
    }

    private static String booleanRepr(final String name, final boolean value)
    {
        final String booleanStr = Boolean.toString(value).substring(0, 1).toUpperCase(Locale.ROOT) + Boolean.toString(value).substring(1);
        return name + ": " + booleanStr + " (" + (value ? 1 : 0) + ")";
    }

    private static String readFromXpath(final String xml, final String path)
    {
        try
        {
            final Document document = xmlToDoc(xml);
            final XPathExpression xPathExpression = XPathFactory.newInstance().newXPath().compile(path);
            final Attr attribute = (Attr)xPathExpression.evaluate(document, XPathConstants.NODE);
            if (attribute == null)
            {
                throw new IllegalArgumentException("Could not find " + path + " in: " + xml);
            }
            return attribute.getNodeValue();
        }
        catch (final XPathExpressionException pnfe)
        {
            throw new AssertionError("Unable to find " + path + " in: " + xml, pnfe);
        }
    }

    private static String readFromXpath(final String xml, final String path, final int pos)
    {
        try
        {
            final Document document = xmlToDoc(xml);
            final XPathExpression xPathExpression = XPathFactory.newInstance().newXPath().compile(path);
            final NodeList attribute = (NodeList)xPathExpression.evaluate(document, XPathConstants.NODESET);
            if (attribute == null)
            {
                throw new IllegalArgumentException("Could not find " + path + " in: " + xml);
            }
            return attribute.item(pos).getNodeValue();
        }
        catch (final XPathExpressionException pnfe)
        {
            throw new AssertionError("Unable to find " + path + " in: " + xml, pnfe);
        }
    }

    private static String fieldByName(final String attribute, final String... names)
    {
        final String path = Arrays.stream(names).map(name -> "/field[@name=\"" + name + "\"]").collect(Collectors.joining());
        return "//packet/proto[@name=\"" + PROTOCOL + "\"]/proto[@name=\"" + PROTOCOL + "\"]/proto[@name=\"" + PROTOCOL + "\"]/proto[@name=\"" + PROTOCOL + "\"]" + path + "/@" + attribute;
    }

    private static String fieldByShowName(final String attribute, final String showName)
    {
        return fieldByShowName(showName) + "/@" + attribute;
    }

    private static String fieldByShowName(final String showName)
    {
        return messagePath() + "/field[@showname=\"" + showName + "\"]";
    }

    private static String messagePath()
    {
        return "//packet/proto[@name=\"" + PROTOCOL + "\"]/proto[@name=\"" + PROTOCOL + "\"]/proto[@name=\"" + PROTOCOL + "\"]/proto[@name=\"" + PROTOCOL + "\"]";
    }

    private static String envelopedMessagePath()
    {
        return messagePath() + "/proto[@name=\"" + PROTOCOL + "\"]" + "/proto[@name=\"" + PROTOCOL + "\"]";
    }

    private static Document xmlToDoc(final String xml)
    {
        final Document documentContext;
        final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        final DocumentBuilder documentBuilder;
        try
        {
            documentBuilder = documentBuilderFactory.newDocumentBuilder();
            documentContext = documentBuilder.parse(new InputSource(new StringReader(xml)));
        }
        catch (final ParserConfigurationException | IOException | SAXException exception)
        {
            throw new IllegalStateException(exception);
        }
        if (documentContext == null)
        {
            throw new AssertionError("Couldn't parse xml document.");
        }
        return documentContext;
    }

    private byte[] sampleMessage(final Frame frame)
    {
        return writeMessage(
                sampleMessageEncoder,
                (buffer, offset) ->
                {
                    sampleMessageEncoder.wrap(buffer, offset)
                            .charField((byte)CHAR_FIELD)
                            .offsetField((byte)OFFSET_FIELD)
                            .char20Field(CHAR_20_FIELD)
                            .int8Field(INT_8_FIELD)
                            .int16Field(INT_16_FIELD)
                            .int32Field(INT_32_FIELD)
                            .int64Field(INT_64_FIELD)
                            .uint8Field(UINT_8_FIELD)
                            .uint16Field(UINT_16_FIELD)
                            .uint32Field(UINT_32_FIELD)
                            .uint64Field(UINT_64_FIELD)
                            .floatField(FLOAT_FIELD)
                            .doubleField(DOUBLE_FIELD);

                    for (int i = 0, int32ArrayFieldLength = INT_32_ARRAY_FIELD.length; i < int32ArrayFieldLength; i++)
                    {
                        final int value = INT_32_ARRAY_FIELD[i];
                        sampleMessageEncoder.int32ArrayField(i, value);
                    }

                    sampleMessageEncoder
                            .compositeField()
                            .compositeField1(COMPOSITE_FIELD_1)
                            .compositeField2(COMPOSITE_FIELD_2)
                            .subComposite()
                            .subCompositeField1(SUB_COMPOSITE_FIELD);
                    sampleMessageEncoder
                            .enumField(ENUM_FIELD)
                            .choiceField()
                            .bacon(BACON)
                            .lettuce(LETTUCE)
                            .tomato(TOMATO);
                    final SampleMessageEncoder.GroupFieldEncoder groupField = sampleMessageEncoder
                            .groupFieldCount(2);

                    groupField
                            .next()
                            .groupFixedLengthField(GROUP_FIXED_LENGTH_FIELD_1);

                    final SampleMessageEncoder.GroupFieldEncoder.SubGroupFieldEncoder subGroup1Encoder = groupField
                            .subGroupFieldCount(2);
                    subGroup1Encoder
                            .next()
                            .subGroupFixedLengthField(SUB_GROUP_FIX_LENGTH_FIELD_1)
                            .subGroupVariableLengthField(SUB_GROUP_VAR_LENGTH_FIELD_1)
                            .next()
                            .subGroupFixedLengthField(SUB_GROUP_FIX_LENGTH_FIELD_2)
                            .subGroupVariableLengthField(SUB_GROUP_VAR_LENGTH_FIELD_2);

                    groupField
                            .groupVariableLengthField(GROUP_VARIABLE_LENGTH_FIELD_1);

                    groupField
                            .next()
                            .groupFixedLengthField(GROUP_FIXED_LENGTH_FIELD_2);

                    final SampleMessageEncoder.GroupFieldEncoder.SubGroupFieldEncoder subGroup2Encoder = groupField
                            .subGroupFieldCount(1)
                            .next();
                    subGroup2Encoder
                            .subGroupFixedLengthField(SUB_GROUP_FIX_LENGTH_FIELD_3)
                            .subGroupVariableLengthField(SUB_GROUP_VAR_LENGTH_FIELD_3);

                    groupField
                            .groupVariableLengthField(GROUP_VARIABLE_LENGTH_FIELD_2);
                    sampleMessageEncoder.varStringField(VAR_STRING_FIELD);
                },
                frame
        );
    }

    private byte[] subProtocolMessage(final Frame frame)
    {
        final ExpandableArrayBuffer buffer = new ExpandableArrayBuffer();

        messageEnvelopeEncoder
                .wrapAndApplyHeader(buffer, frameSize(frame), sampleHeaderEncoder)
                .charField((byte)ENVELOPE_CHAR_FIELD);

        subProtocolMessageEncoder
                .wrapAndApplyHeader(buffer, frameSize(frame) + sampleHeaderEncoder.encodedLength() + messageEnvelopeEncoder.encodedLength(), clobHeaderEncoder)
                .int64Field(INT_64_FIELD);

        writeFrame(
                buffer,
                sampleHeaderEncoder.encodedLength() +
                messageEnvelopeEncoder.encodedLength() +
                clobHeaderEncoder.encodedLength() +
                subProtocolMessageEncoder.encodedLength(),
                frame
        );
        final byte[] output = new byte[
                frameSize(frame) +
                sampleHeaderEncoder.encodedLength() +
                messageEnvelopeEncoder.encodedLength() +
                clobHeaderEncoder.encodedLength() +
                subProtocolMessageEncoder.encodedLength()
                ];
        buffer.getBytes(0, output, 0, output.length);
        return output;
    }

    private void writeFrame(final MutableDirectBuffer buffer, final int length, final Frame frame)
    {
        for (int i = 0; i < frame.offsetToMessageLength(); i++)
        {
            buffer.putByte(i, Byte.MAX_VALUE);
        }
        buffer.putInt(frame.offsetToMessageLength(), frame.lengthIncludesFrame() ? length + frameSize(frame) : length, ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < frame.additionalDataInFrameLength(); i++)
        {
            buffer.putByte(frame.offsetToMessageLength() + frame.messageLengthType().lengthInBytes() + i, Byte.MAX_VALUE);
        }
    }

    private byte[] writeMessage(final MessageFlyweight messageFlyweight, final MessageWriter writer, final Frame frame)
    {
        final ExpandableArrayBuffer message = new ExpandableArrayBuffer();
        sampleHeaderEncoder
                .wrap(message, frameSize(frame))
                .blockLength(messageFlyweight.sbeBlockLength())
                .templateId(messageFlyweight.sbeTemplateId())
                .schemaId(messageFlyweight.sbeSchemaId())
                .version(messageFlyweight.sbeSchemaVersion());

        writer.writeMessage(message, frameSize(frame) + sampleHeaderEncoder.encodedLength());

        writeFrame(message, sampleHeaderEncoder.encodedLength() + messageFlyweight.encodedLength(), frame);
        final byte[] output = new byte[frameSize(frame) + sampleHeaderEncoder.encodedLength() + messageFlyweight.encodedLength()];
        message.getBytes(0, output, 0, output.length);
        return output;
    }

    private byte[] writeSubProtocolMessage(final MessageFlyweight messageFlyweight, final MessageWriter writer, final Frame frame)
    {
        final ExpandableArrayBuffer message = new ExpandableArrayBuffer();
        subProtocolHeaderEncoder
                .wrap(message, frameSize(frame))
                .blockLength(messageFlyweight.sbeBlockLength())
                .templateId(messageFlyweight.sbeTemplateId())
                .schemaId(messageFlyweight.sbeSchemaId())
                .version(messageFlyweight.sbeSchemaVersion());

        writer.writeMessage(message, frameSize(frame) + subProtocolHeaderEncoder.encodedLength());

        writeFrame(message, subProtocolHeaderEncoder.encodedLength() + messageFlyweight.encodedLength(), frame);
        final byte[] output = new byte[frameSize(frame) + subProtocolHeaderEncoder.encodedLength() + messageFlyweight.encodedLength()];
        message.getBytes(0, output, 0, output.length);
        return output;
    }

    @SuppressWarnings("SystemOut")
    private String pcapToXml(final byte[] toWrite, final File luaScript)
    {
        final ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", "tshark -oconsole.log.level:252 -r - -T pdml -X lua_script:" + luaScript.getAbsolutePath());
        try
        {
            final Process process = processBuilder.start();
            try (final OutputStream outputStream = process.getOutputStream())
            {
                outputStream.write(toWrite);
            }

            try (final InputStream errStream = process.getErrorStream())
            {
                System.err.println(new String(errStream.readAllBytes(), Charset.defaultCharset()));
            }

            try (final InputStream inputStream = process.getInputStream())
            {
                return new String(inputStream.readAllBytes(), Charset.defaultCharset());
            }
        }
        catch (final IOException e)
        {
            throw new UncheckedIOException(e);
        }
    }

    private int frameSize(final Frame frame)
    {
        return frame.offsetToMessageLength() + frame.messageLengthType().lengthInBytes() + frame.additionalDataInFrameLength();
    }

    private byte[] writeToPcapFormat(final int destPort, final SetUp setUp, final byte[]... messages)
    {
        final ExpandableArrayBuffer buffer = new ExpandableArrayBuffer();
        final int totalDataWritten = PcapFile.writePcap(buffer, 53086, destPort, messages);
        final byte[] output = Arrays.copyOf(buffer.byteArray(), totalDataWritten);
        try
        {
            if (SHOULD_DUMP)
            {
                final Path dump = Files.createTempFile("dump", ".pcap");
                dumpOutput.println("wireshark -X lua_script:" + setUp.luaScript().toString() + " " + dump);
                Files.write(dump, output);
            }
        }
        catch (final IOException e)
        {
            throw new UncheckedIOException(e);
        }
        return output;
    }

    @FunctionalInterface
    private interface MessageWriter
    {
        void writeMessage(final MutableDirectBuffer buffer, final int offset);
    }

    private static final class SetUp
    {
        private Frame frame = new Frame(SimpleType.INT32, 5, 3, false);
        private File luaScript;

        private SetUp()
        {
        }

        public static SetUp createSetUp()
        {
            return new SetUp();
        }

        public SetUp withFrame(final Frame frame)
        {
            this.frame = frame;
            return this;
        }

        public Frame frame()
        {
            return frame;
        }

        public File buildDissector()
        {
            try
            {
                luaScript = File.createTempFile(PROTOCOL + "_protocol", ".lua");
                if (!SHOULD_DUMP)
                {
                    luaScript.deleteOnExit();
                }
            }
            catch (final IOException e)
            {
                throw new UncheckedIOException(e);
            }
            try (final OutputStream outputStream = new FileOutputStream(luaScript))
            {
                SbeLuaGenerator.generateLuaDissector(
                        PROTOCOL + "_protocol",
                        PROTOCOL_PRETTY_NAME,
                        PROTOCOL_PRETTY_NAME + " Protocol",
                        outputStream,
                        frame,
                        new int[]{PROTOCOL_DEST_PORT},
                        Schema.schema(readSchemaFromClassPath("/sample-schema.xml"), "sample", Set.of("MessageEnvelope")),
                        Schema.schema(readSchemaFromClassPath("/sub-protocol-schema.xml"), "subProtocol", Collections.emptySet())
                );
            }
            catch (final IOException e)
            {
                throw new UncheckedIOException(e);
            }
            return luaScript;
        }

        public File luaScript()
        {
            return luaScript;
        }
    }
}

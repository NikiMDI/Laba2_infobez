package com.nikita.stage1;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Dependency-free checks: run this class with assertions enabled or disabled. */
public final class PeHeaderParserTest {
    private static final int DEFAULT_PE_OFFSET = 128;
    private static final int DEFAULT_FILE_SIZE = 1024;
    private static final int HEADER_SIZE = 512;
    private static final long PE32_IMAGE_BASE = 0xFEDC0000L;
    private static final long PE32_PLUS_IMAGE_BASE = 0xFEDCBA9876540000L;

    private final PeHeaderParser parser = new PeHeaderParser();
    private final List<Path> ownFiles = new ArrayList<>();
    private final Path temporaryDirectory;
    private int completedTests;

    private PeHeaderParserTest(Path temporaryDirectory) {
        this.temporaryDirectory = temporaryDirectory;
    }

    public static void main(String[] arguments) throws Exception {
        Path directory = Files.createTempDirectory("pe-header-tests-");
        PeHeaderParserTest suite = new PeHeaderParserTest(directory);
        try {
            suite.runAll();
            System.out.println("OK: " + suite.completedTests + " tests passed.");
        } finally {
            // Delete only paths created by this test suite, without recursive traversal.
            for (Path path : suite.ownFiles) {
                Files.deleteIfExists(path);
            }
            Files.deleteIfExists(directory);
        }
    }

    private void runAll() throws Exception {
        run("PE32 headers and unsigned 32-bit fields", () -> {
            Path path = writeFixture("пример PE 32.exe", fixture(false));
            PeHeaders headers = parser.parse(path);
            check(headers.path().toAbsolutePath().normalize().equals(path.toAbsolutePath().normalize()),
                    "The result must identify the input file");
            check(headers.fileSize() == DEFAULT_FILE_SIZE, "File size");
            check(headers.peOffset() == DEFAULT_PE_OFFSET, "PE offset");
            check(headers.machine() == 0x014C, "Machine");
            check(headers.numberOfSections() == 1, "Section count");
            check(headers.optionalHeaderSize() == 224, "Optional Header size");
            check(headers.format() == PeFormat.PE32, "PE32 format");
            check(headers.entryPointRva() == 0x1000L, "Entry point RVA");
            check(headers.imageBase() == PE32_IMAGE_BASE, "Unsigned PE32 ImageBase");
            check(headers.sizeOfImage() == 8192L, "SizeOfImage");
            check(headers.sizeOfHeaders() == HEADER_SIZE, "SizeOfHeaders");
            check(headers.numberOfDataDirectories() == 16L, "Data Directory count");
            check(headers.sectionTableOffset() == 376L, "Section table offset");
            check(headers.characteristics() == 0x0102, "COFF characteristics");
            check(headers.subsystem() == 3, "Subsystem");
        });

        run("PE32+ headers and unsigned 64-bit ImageBase", () -> {
            PeHeaders headers = parseFixture("pe32-plus.dll", fixture(true));
            check(headers.format() == PeFormat.PE32_PLUS, "PE32+ format");
            check(headers.machine() == 0x8664, "AMD64 machine");
            check(headers.optionalHeaderSize() == 240, "PE32+ Optional Header size");
            check(headers.imageBase() == PE32_PLUS_IMAGE_BASE, "All 64 ImageBase bits");
            check(Long.toUnsignedString(headers.imageBase(), 16).equals("fedcba9876540000"),
                    "Unsigned ImageBase rendering");
            check(headers.entryPointRva() == 0x1000L, "PE32+ entry point remains 32-bit");
            check(headers.numberOfDataDirectories() == 16L, "PE32+ directory count");
            check(headers.sectionTableOffset() == 392L, "PE32+ section table offset");
            check(headers.characteristics() == 0x2022, "DLL characteristics in COFF");
        });

        run("PE signature at a different file offset", () -> {
            PeHeaders headers = parseFixture("moved.exe", fixture(true, 192, 240, 16, 1, 1024, 512));
            check(headers.peOffset() == 192L, "Read e_lfanew instead of a fixed position");
            check(headers.sectionTableOffset() == 456L, "Moved section table");
            check(headers.imageBase() == PE32_PLUS_IMAGE_BASE, "Moved Optional Header");
        });

        run("PE signature immediately after the DOS header", () -> {
            PeHeaders headers = parseFixture("minimal-stub.exe", fixture(false, 64, 224, 16, 1, 1024, 512));
            check(headers.peOffset() == 64L, "Smallest accepted e_lfanew");
            check(headers.sectionTableOffset() == 312L, "Section table follows the actual headers");
        });

        run("Optional Header larger than the usual size", () -> {
            PeHeaders headers = parseFixture("extended-optional.exe", fixture(false, 128, 248, 16, 1, 1024, 512));
            check(headers.optionalHeaderSize() == 248, "Preserve declared Optional Header size");
            check(headers.sectionTableOffset() == 400L, "Skip the entire declared Optional Header");
        });

        run("PE32 Optional Header without Data Directories", () -> {
            PeHeaders headers = parseFixture("pe32-no-directories.exe", fixture(false, 128, 96, 0, 1, 1024, 512));
            check(headers.numberOfDataDirectories() == 0L, "Zero Data Directories are allowed");
            check(headers.sectionTableOffset() == 248L, "PE32 fixed Optional Header size");
        });

        run("PE32+ Optional Header without Data Directories", () -> {
            PeHeaders headers = parseFixture("pe32-plus-no-directories.exe", fixture(true, 128, 112, 0, 1, 1024, 512));
            check(headers.numberOfDataDirectories() == 0L, "PE32+ zero Data Directories");
            check(headers.sectionTableOffset() == 264L, "PE32+ fixed Optional Header size");
        });

        run("Optional Header with one directory", () -> {
            PeHeaders headers = parseFixture("one-directory.exe", fixture(false, 128, 104, 1, 1, 1024, 512));
            check(headers.numberOfDataDirectories() == 1L, "Use the declared directory count");
            check(headers.optionalHeaderSize() == 104, "Variable-sized directory array");
        });

        run("Unknown Machine value does not change the PE format", () -> {
            byte[] bytes = fixture(true);
            put16(bytes, DEFAULT_PE_OFFSET + 4, 0xFFFF);
            PeHeaders headers = parseFixture("unknown-machine.exe", bytes);
            check(headers.machine() == 0xFFFF, "Machine is unsigned");
            check(headers.format() == PeFormat.PE32_PLUS, "Magic determines the Optional Header layout");
        });

        run("More than 96 sections are parsed without OS loading validation", () -> {
            PeHeaders headers = parseFixture("many-sections.exe", fixture(false, 128, 224, 16, 97, 8192, 8192));
            check(headers.numberOfSections() == 97, "Parser must not impose a loader section limit");
        });

        run("Invalid MZ signature", () -> {
            byte[] bytes = fixture(false);
            bytes[0] = 'X';
            expectInvalid("bad-mz.exe", bytes);
        });

        run("Invalid PE signature", () -> {
            byte[] bytes = fixture(false);
            bytes[DEFAULT_PE_OFFSET + 2] = 1;
            expectInvalid("bad-pe.exe", bytes);
        });

        run("Unsupported Optional Header magic", () -> {
            byte[] bytes = fixture(false);
            put16(bytes, optionalOffset(DEFAULT_PE_OFFSET), 0x0107);
            expectInvalid("unsupported-magic.exe", bytes);
        });

        run("Truncated DOS header", () -> expectInvalid("short-dos.exe", Arrays.copyOf(fixture(false), 63)));

        run("Unsigned e_lfanew outside the file", () -> {
            byte[] bytes = fixture(false);
            put32(bytes, 0x3C, 0xFFFFFFF0L);
            expectInvalid("large-pe-offset.exe", bytes);
        });

        run("e_lfanew overlaps the DOS header", () -> {
            byte[] bytes = fixture(false);
            put32(bytes, 0x3C, 63);
            expectInvalid("overlapping-pe-offset.exe", bytes);
        });

        run("Truncated PE signature", () -> expectInvalid("short-pe.exe",
                Arrays.copyOf(fixture(false), DEFAULT_PE_OFFSET + 3)));

        run("Truncated COFF header", () -> expectInvalid("short-coff.exe",
                Arrays.copyOf(fixture(false), DEFAULT_PE_OFFSET + 4 + 19)));

        run("Truncated Optional Header", () -> expectInvalid("short-optional.exe",
                Arrays.copyOf(fixture(false), optionalOffset(DEFAULT_PE_OFFSET) + 223)));

        run("Truncated section table", () -> {
            byte[] bytes = Arrays.copyOf(fixture(false), 376 + 39);
            put32(bytes, optionalOffset(DEFAULT_PE_OFFSET) + 60, bytes.length);
            expectInvalid("short-sections.exe", bytes);
        });

        run("Declared PE32 Optional Header is too short", () -> {
            byte[] bytes = fixture(false);
            put16(bytes, DEFAULT_PE_OFFSET + 4 + 16, 95);
            expectInvalid("small-pe32-optional.exe", bytes);
        });

        run("Declared PE32+ Optional Header is too short", () -> {
            byte[] bytes = fixture(true);
            put16(bytes, DEFAULT_PE_OFFSET + 4 + 16, 111);
            expectInvalid("small-pe32-plus-optional.exe", bytes);
        });

        run("Declared Optional Header extends beyond the file", () -> {
            byte[] bytes = fixture(false);
            put16(bytes, DEFAULT_PE_OFFSET + 4 + 16, 1000);
            expectInvalid("oversized-optional.exe", bytes);
        });

        run("SizeOfHeaders does not include the complete section table", () -> {
            byte[] bytes = fixture(false);
            put32(bytes, optionalOffset(DEFAULT_PE_OFFSET) + 60, 415);
            expectInvalid("small-headers.exe", bytes);
        });

        run("SizeOfHeaders exceeds the file size", () -> {
            byte[] bytes = fixture(false);
            put32(bytes, optionalOffset(DEFAULT_PE_OFFSET) + 60, 1025);
            expectInvalid("oversized-headers.exe", bytes);
        });

        run("PE32 directory count exceeds Optional Header capacity", () -> {
            byte[] bytes = fixture(false);
            put32(bytes, optionalOffset(DEFAULT_PE_OFFSET) + 92, 17);
            expectInvalid("too-many-pe32-directories.exe", bytes);
        });

        run("PE32+ directory count exceeds Optional Header capacity", () -> {
            byte[] bytes = fixture(true);
            put32(bytes, optionalOffset(DEFAULT_PE_OFFSET) + 108, 17);
            expectInvalid("too-many-pe32-plus-directories.exe", bytes);
        });

        run("Unsigned maximum directory count is rejected without overflow", () -> {
            byte[] bytes = fixture(false);
            put32(bytes, optionalOffset(DEFAULT_PE_OFFSET) + 92, 0xFFFFFFFFL);
            expectInvalid("unsigned-directory-count.exe", bytes);
        });

        run("Missing file produces IOException", () -> {
            Path missingFile = temporaryDirectory.resolve("this-file-was-never-created.exe");
            try {
                parser.parse(missingFile);
                throw new AssertionError("Expected IOException for a missing file");
            } catch (IOException expected) {
                // A filesystem error must remain distinguishable from malformed file contents.
            }
        });
    }

    private PeHeaders parseFixture(String fileName, byte[] bytes) throws IOException, PeFormatException {
        return parser.parse(writeFixture(fileName, bytes));
    }

    private Path writeFixture(String fileName, byte[] bytes) throws IOException {
        Path path = temporaryDirectory.resolve(fileName);
        ownFiles.add(path);
        Files.write(path, bytes);
        return path;
    }

    private void expectInvalid(String fileName, byte[] bytes) throws IOException, PeFormatException {
        Path path = writeFixture(fileName, bytes);
        try {
            parser.parse(path);
            throw new AssertionError("Expected PeFormatException for " + fileName);
        } catch (PeFormatException expected) {
            check(expected.getMessage() != null && !expected.getMessage().isBlank(),
                    "A malformed file needs an explanatory error message");
        }
    }

    private void run(String name, CheckedTest test) throws Exception {
        try {
            test.execute();
            completedTests++;
        } catch (Exception | AssertionError failure) {
            throw new AssertionError("Test failed: " + name, failure);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static byte[] fixture(boolean pe32Plus) {
        return fixture(pe32Plus, DEFAULT_PE_OFFSET, pe32Plus ? 240 : 224, 16, 1,
                DEFAULT_FILE_SIZE, HEADER_SIZE);
    }

    private static byte[] fixture(boolean pe32Plus, int peOffset, int optionalSize,
                                  int directoryCount, int sections, int fileSize, int sizeOfHeaders) {
        byte[] bytes = new byte[fileSize];
        bytes[0] = 'M';
        bytes[1] = 'Z';
        put32(bytes, 0x3C, peOffset);
        bytes[peOffset] = 'P';
        bytes[peOffset + 1] = 'E';

        int coff = peOffset + 4;
        put16(bytes, coff, pe32Plus ? 0x8664 : 0x014C);
        put16(bytes, coff + 2, sections);
        put32(bytes, coff + 4, 0x65010203L);
        put16(bytes, coff + 16, optionalSize);
        put16(bytes, coff + 18, pe32Plus ? 0x2022 : 0x0102);

        int optional = optionalOffset(peOffset);
        put16(bytes, optional, pe32Plus ? 0x020B : 0x010B);
        put32(bytes, optional + 4, 512);
        put32(bytes, optional + 16, 0x1000);
        put32(bytes, optional + 20, 0x1000);
        if (pe32Plus) {
            put64(bytes, optional + 24, PE32_PLUS_IMAGE_BASE);
        } else {
            put32(bytes, optional + 24, 0x1000);
            put32(bytes, optional + 28, PE32_IMAGE_BASE);
        }
        put32(bytes, optional + 32, 0x1000);
        put32(bytes, optional + 36, 0x200);
        put32(bytes, optional + 56, 8192);
        put32(bytes, optional + 60, sizeOfHeaders);
        put16(bytes, optional + 68, 3);
        put32(bytes, optional + (pe32Plus ? 108 : 92), directoryCount);

        int sectionTable = optional + optionalSize;
        byte[] name = ".text".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(name, 0, bytes, sectionTable, name.length);
        put32(bytes, sectionTable + 8, 512);
        put32(bytes, sectionTable + 12, 0x1000);
        put32(bytes, sectionTable + 16, 512);
        put32(bytes, sectionTable + 20, sizeOfHeaders);
        put32(bytes, sectionTable + 36, 0x60000020L);
        return bytes;
    }

    private static int optionalOffset(int peOffset) {
        return peOffset + 4 + 20;
    }

    private static void put16(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) value;
        bytes[offset + 1] = (byte) (value >>> 8);
    }

    private static void put32(byte[] bytes, int offset, long value) {
        for (int index = 0; index < 4; index++) {
            bytes[offset + index] = (byte) (value >>> (8 * index));
        }
    }

    private static void put64(byte[] bytes, int offset, long value) {
        for (int index = 0; index < 8; index++) {
            bytes[offset + index] = (byte) (value >>> (8 * index));
        }
    }

    @FunctionalInterface
    private interface CheckedTest {
        void execute() throws Exception;
    }
}

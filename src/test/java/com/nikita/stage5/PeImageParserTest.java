package com.nikita.stage5;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class PeImageParserTest {
    private static final int PE_OFFSET = 128;
    private static final int FILE_SIZE = 2048;
    private static final int HEADERS_SIZE = 512;
    private static final int FIRST_RAW_OFFSET = 0x200;
    private static final int SECOND_RAW_OFFSET = 0x600;
    private static final int RAW_SIZE = 0x200;
    private static final long IMPORT_RVA = 0x3040;

    private final PeImageParser parser = new PeImageParser();
    private final List<Path> ownFiles = new ArrayList<>();
    private final Path directory;
    private int completedTests;

    private PeImageParserTest(Path directory) {
        this.directory = directory;
    }

    public static void main(String[] arguments) throws Exception {
        Path directory = Files.createTempDirectory("pe-stage5-image-tests-");
        PeImageParserTest suite = new PeImageParserTest(directory);
        try {
            suite.runAll();
            System.out.println("OK: " + suite.completedTests + " base image tests passed (stage 5).");
        } finally {
            for (Path file : suite.ownFiles) {
                Files.deleteIfExists(file);
            }
            Files.deleteIfExists(directory);
        }
    }

    private void runAll() throws Exception {
        run("PE32 sections and import position", () -> {
            Fixture fixture = fixture(false);
            PeImage image = parse("пример PE32.exe", fixture.bytes());
            check(image.headers().format() == PeFormat.PE32, "PE32 format");
            check(image.sections().size() == 2, "Section count");
            PeSection first = image.sections().get(0);
            check(first.index() == 0, "Zero-based section index");
            check(first.headerOffset() == fixture.sectionTableOffset(), "Section header location");
            check(first.name().equals(".text"), "Section name");
            check(first.virtualAddress() == 0x1000, "Section RVA");
            check(first.virtualSize() == 0x180, "Virtual size");
            check(first.pointerToRawData() == FIRST_RAW_OFFSET, "Raw data offset");
            check(first.sizeOfRawData() == RAW_SIZE, "Raw data size");
            check(first.characteristics() == 0x60000020L, "Unsigned section flags");
            PeDataDirectory imports = image.importDirectory().orElseThrow();
            check(imports.entryOffset() == fixture.importEntryOffset(), "Directory slot position");
            check(imports.rva() == IMPORT_RVA, "Import RVA");
            check(imports.size() == 40, "Import size");
            RvaMapper.Mapping mapping = mapper(image).map(imports.rva(), 20);
            check(mapping.rva() == IMPORT_RVA && mapping.length() == 20, "Mapping identifies the request");
            check(mapping.fileOffset() == 0x640, "Import RVA must be converted to file offset");
            check(mapping.section().orElseThrow().name().equals(".custom"), "Import section");
        });

        run("PE32+ uses the correct directory layout and import index", () -> {
            Fixture fixture = fixture(true);
            put32(fixture.bytes(), fixture.importEntryOffset() - 8, 0xFFFF0000L);
            put32(fixture.bytes(), fixture.importEntryOffset() - 4, 0x200);
            PeImage image = parse("pe32-plus.exe", fixture.bytes());
            check(image.headers().format() == PeFormat.PE32_PLUS, "PE32+ format");
            check(image.importDirectory().orElseThrow().entryOffset() == 272,
                    "PE32+ import slot is Optional Header + 120");
            check(mapper(image).map(IMPORT_RVA, 20).fileOffset() == 0x640,
                    "Do not use the export directory or PE32 directory offset");
        });

        run("Moved PE and expanded Optional Header move the section table", () -> {
            Fixture fixture = fixture(false, 160, 248);
            PeImage image = parse("moved-headers.exe", fixture.bytes());
            check(image.headers().sectionTableOffset() == 432, "Actual Optional Header length");
            check(image.sections().get(0).headerOffset() == 432, "First section header follows Optional Header");
            check(image.sections().get(1).headerOffset() == 472, "40-byte section stride");
            check(mapper(image).map(IMPORT_RVA, 20).fileOffset() == 0x640, "Moved headers preserve data mapping");
        });

        run("Section header order is preserved while virtual overlap is still rejected", () -> {
            Fixture fixture = fixture(false);
            int table = fixture.sectionTableOffset();
            byte[] firstHeader = new byte[40];
            System.arraycopy(fixture.bytes(), table, firstHeader, 0, 40);
            System.arraycopy(fixture.bytes(), table + 40, fixture.bytes(), table, 40);
            System.arraycopy(firstHeader, 0, fixture.bytes(), table + 40, 40);
            PeImage image = parse("reordered-sections.exe", fixture.bytes());
            check(image.sections().get(0).name().equals(".custom"), "Keep the original first header");
            check(image.sections().get(1).name().equals(".text"), "Keep the original second header");
            check(image.sections().get(0).index() == 0, "Index is based on file table order");
            check(image.sections().get(0).headerOffset() == table, "Header position remains physical");
            check(mapper(image).map(IMPORT_RVA, 20).fileOffset() == 0x640, "Mapping does not require sorted input");
            check(mapper(image).map(0x1010, 1).fileOffset() == 0x210, "Code mapping after reordering");

            byte[] overlapping = fixture.bytes().clone();
            put32(overlapping, table + 12, 0x1100);
            put32(overlapping, fixture.importEntryOffset(), 0);
            put32(overlapping, fixture.importEntryOffset() + 4, 0);
            expectInvalid("reordered-virtual-overlap.exe", overlapping);
        });

        run("Import section name need not be .idata and can occupy all eight bytes", () -> {
            Fixture fixture = fixture(false);
            writeName(fixture.bytes(), fixture.sectionTableOffset() + 40, "NETDATA!");
            PeImage image = parse("renamed-section.exe", fixture.bytes());
            check(image.sections().get(1).name().equals("NETDATA!"), "Eight-byte name without trailing NUL");
            check(mapper(image).map(IMPORT_RVA, 20).fileOffset() == 0x640,
                    "Section name does not determine import position");
        });

        run("Changed section RVA and raw offset change import mapping", () -> {
            Fixture fixture = fixture(true);
            int second = fixture.sectionTableOffset() + 40;
            put32(fixture.bytes(), second + 12, 0x7000);
            put32(fixture.bytes(), second + 20, 0x400);
            put32(fixture.bytes(), fixture.importEntryOffset(), 0x7040);
            put32(fixture.bytes(), fixture.optionalOffset() + 56, 0x9000);
            PeImage image = parse("moved-import-section.exe", fixture.bytes());
            RvaMapper.Mapping mapping = mapper(image).map(0x7040, 20);
            check(mapping.fileOffset() == 0x440, "Use PointerToRawData and section RVA");
            check(mapping.section().orElseThrow().virtualAddress() == 0x7000, "Select the moved section");
        });

        run("Entry point RVA maps inside the code section", () -> {
            PeImage image = parse("entry-point.exe", fixture(false).bytes());
            RvaMapper.Mapping mapping = mapper(image).map(image.headers().entryPointRva(), 1);
            check(mapping.fileOffset() == 0x210, "Entry point raw offset");
            check(mapping.section().orElseThrow().name().equals(".text"), "Entry point section");
        });

        run("Header RVA maps to the same file offset but must stay inside headers", () -> {
            PeImage image = parse("header-rva.exe", fixture(false).bytes());
            RvaMapper.Mapping mapping = mapper(image).map(0x40, 4);
            check(mapping.fileOffset() == 0x40, "Header RVA equals its raw offset");
            check(mapping.section().isEmpty(), "Headers have no section record");
            expectMappingError(mapper(image), 0x1F8, 16);
        });

        run("Raw padding remains addressable when raw size exceeds VirtualSize", () -> {
            PeImage image = parse("raw-padding.exe", fixture(false).bytes());
            check(mapper(image).map(0x31F0, 16).fileOffset() == 0x7F0,
                    "Use max(VirtualSize, SizeOfRawData) for section membership");
        });

        run("Missing import slot is not read when the declared directory count is too small", () -> {
            for (int count = 0; count <= 1; count++) {
                Fixture fixture = fixture(false);
                put32(fixture.bytes(), fixture.optionalOffset() + 92, count);
                put32(fixture.bytes(), fixture.importEntryOffset(), 0xFFFFFFFFL);
                put32(fixture.bytes(), fixture.importEntryOffset() + 4, 0xFFFFFFFFL);
                PeImage image = parse("no-import-slot-" + count + ".exe", fixture.bytes());
                check(image.importDirectory().isEmpty(), "Unavailable slot means no declared import directory");
            }
        });

        run("Zero RVA and zero size represent an absent import directory", () -> {
            Fixture fixture = fixture(true);
            put32(fixture.bytes(), fixture.importEntryOffset(), 0);
            put32(fixture.bytes(), fixture.importEntryOffset() + 4, 0);
            check(parse("empty-import.exe", fixture.bytes()).importDirectory().isEmpty(),
                    "Zero directory is absent");
        });

        run("Nonzero import RVA with zero size is rejected", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.importEntryOffset() + 4, 0);
            expectInvalid("zero-import-size.exe", fixture.bytes());
        });

        run("Nonzero import size with zero RVA is rejected", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.importEntryOffset(), 0);
            expectInvalid("zero-import-rva.exe", fixture.bytes());
        });

        run("Import directory must fit its first 20-byte descriptor", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.importEntryOffset() + 4, 19);
            expectInvalid("short-import-directory.exe", fixture.bytes());
        });

        run("Import RVA in an unmapped gap is rejected", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.importEntryOffset(), 0x2000);
            expectInvalid("unmapped-import.exe", fixture.bytes());
        });

        run("Import in a zero-filled virtual tail has no file bytes", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.sectionTableOffset() + 40 + 8, 0x400);
            put32(fixture.bytes(), fixture.importEntryOffset(), 0x3280);
            expectInvalid("virtual-tail-import.exe", fixture.bytes());
        });

        run("First import descriptor cannot cross the end of raw section data", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.importEntryOffset(), 0x31F8);
            expectInvalid("import-crosses-raw-end.exe", fixture.bytes());
        });

        run("Raw ranges and mapped reads must stay within the actual file", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.sectionTableOffset() + 40 + 20, 0x780);
            expectInvalid("raw-outside-file.exe", fixture.bytes());
            PeImage valid = parse("valid-for-range-check.exe", fixture(false).bytes());
            PeSection bad = new PeSection(0, 0, ".bad", 0x200, 0x1000,
                    0x200, FILE_SIZE - 48, 0);
            expectMappingError(new RvaMapper(valid.headers(), List.of(bad)), 0x1000, 64);
        });

        run("Section raw data may reference bytes inside the file headers", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.sectionTableOffset() + 20, 0x100);
            PeImage image = parse("raw-overlaps-headers.exe", fixture.bytes());
            RvaMapper.Mapping sectionMapping = mapper(image).map(0x1010, 1);
            check(sectionMapping.fileOffset() == 0x110, "Section RVA uses its declared raw pointer");
            check(sectionMapping.section().orElseThrow().name().equals(".text"),
                    "Section ownership is determined by RVA");
            RvaMapper.Mapping headerMapping = mapper(image).map(0x110, 1);
            check(headerMapping.fileOffset() == 0x110, "Header RVA still maps directly");
            check(headerMapping.section().isEmpty(), "Shared file bytes do not make RVA regions ambiguous");
        });

        run("Different RVA sections may reference shared raw file bytes", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.sectionTableOffset() + 40 + 20, FIRST_RAW_OFFSET + 0x100);
            PeImage image = parse("raw-sections-overlap.exe", fixture.bytes());
            RvaMapper.Mapping imports = mapper(image).map(IMPORT_RVA, 20);
            RvaMapper.Mapping code = mapper(image).map(0x1140, 20);
            check(imports.fileOffset() == 0x340, "Import RVA uses the second section raw pointer");
            check(code.fileOffset() == imports.fileOffset(), "Different RVAs can identify the same file bytes");
            check(imports.section().orElseThrow().name().equals(".custom"), "Import RVA section");
            check(code.section().orElseThrow().name().equals(".text"), "Code RVA section");
        });

        run("Section virtual span cannot exceed the 32-bit RVA space", () -> {
            Fixture fixture = fixture(true);
            put32(fixture.bytes(), fixture.sectionTableOffset() + 40 + 12, 0xFFFFFF80L);
            expectInvalid("section-rva-overflow.exe", fixture.bytes());
        });

        run("Import directory range cannot overflow the 32-bit RVA space", () -> {
            Fixture fixture = fixture(true);
            put32(fixture.bytes(), fixture.importEntryOffset(), 0xFFFFFFF0L);
            put32(fixture.bytes(), fixture.importEntryOffset() + 4, 0x40);
            expectInvalid("import-rva-overflow.exe", fixture.bytes());
        });

        run("Negative RVA is rejected", () -> {
            PeImage image = parse("negative-rva.exe", fixture(false).bytes());
            expectMappingError(mapper(image), -1, 1);
        });

        run("RVA and requested range must fit unsigned 32-bit coordinates", () -> {
            PeImage image = parse("unsigned-rva-limits.exe", fixture(false).bytes());
            expectMappingError(mapper(image), 0x1_0000_0000L, 1);
            expectMappingError(mapper(image), 0xFFFFFFFFL, 2);
            expectMappingError(mapper(image), 0x1000, Long.MAX_VALUE);
        });

        run("Empty and negative mapped read lengths are rejected", () -> {
            PeImage image = parse("invalid-map-length.exe", fixture(false).bytes());
            expectMappingError(mapper(image), 0x1000, 0);
            expectMappingError(mapper(image), 0x1000, -1);
        });

        run("An overlapping mapped region makes a requested range ambiguous", () -> {
            PeImage image = parse("valid-for-overlap-check.exe", fixture(false).bytes());
            PeSection first = image.sections().get(0);
            PeSection overlapping = new PeSection(1, 0, ".overlap", 0x200, 0x1100,
                    0x200, SECOND_RAW_OFFSET, 0);
            RvaMapper mapper = new RvaMapper(image.headers(), List.of(first, overlapping));
            expectMappingError(mapper, 0x1080, 0x100);
            PeSection insideHeaders = new PeSection(0, 0, ".header", 0x100, 0x80,
                    0x100, SECOND_RAW_OFFSET, 0);
            expectMappingError(new RvaMapper(image.headers(), List.of(insideHeaders)), 0x60, 0x40);
        });
    }

    private static RvaMapper mapper(PeImage image) {
        return new RvaMapper(image.headers(), image.sections());
    }

    private PeImage parse(String fileName, byte[] bytes) throws IOException, PeFormatException {
        Path path = directory.resolve(fileName);
        ownFiles.add(path);
        Files.write(path, bytes);
        return parser.parse(path);
    }

    private void expectInvalid(String fileName, byte[] bytes) throws IOException, PeFormatException {
        try {
            parse(fileName, bytes);
            throw new AssertionError("Expected PeFormatException for " + fileName);
        } catch (PeFormatException expected) {
            check(expected.getMessage() != null && !expected.getMessage().isBlank(),
                    "Malformed data needs an explanatory error");
        }
    }

    private static void expectMappingError(RvaMapper mapper, long rva, long length)
            throws PeFormatException {
        try {
            mapper.map(rva, length);
            throw new AssertionError("Expected mapping failure for RVA " + rva + ", length " + length);
        } catch (PeFormatException expected) {
            check(expected.getMessage() != null && !expected.getMessage().isBlank(),
                    "Invalid mapping needs an explanatory error");
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

    private static Fixture fixture(boolean plus) {
        return fixture(plus, PE_OFFSET, plus ? 240 : 224);
    }

    private static Fixture fixture(boolean plus, int peOffset, int optionalSize) {
        byte[] bytes = new byte[FILE_SIZE];
        bytes[0] = 'M';
        bytes[1] = 'Z';
        put32(bytes, 0x3C, peOffset);
        bytes[peOffset] = 'P';
        bytes[peOffset + 1] = 'E';
        int coff = peOffset + 4;
        put16(bytes, coff, plus ? 0x8664 : 0x014C);
        put16(bytes, coff + 2, 2);
        put16(bytes, coff + 16, optionalSize);
        put16(bytes, coff + 18, plus ? 0x22 : 0x102);
        int optional = coff + 20;
        put16(bytes, optional, plus ? 0x20B : 0x10B);
        put32(bytes, optional + 16, 0x1010);
        if (plus) {
            put64(bytes, optional + 24, 0x140000000L);
        } else {
            put32(bytes, optional + 28, 0x400000);
        }
        put32(bytes, optional + 32, 0x1000);
        put32(bytes, optional + 36, 0x200);
        put32(bytes, optional + 56, 0x5000);
        put32(bytes, optional + 60, HEADERS_SIZE);
        put16(bytes, optional + 68, 3);
        put32(bytes, optional + (plus ? 108 : 92), 16);
        int importEntry = optional + (plus ? 112 : 96) + 8;
        put32(bytes, importEntry, IMPORT_RVA);
        put32(bytes, importEntry + 4, 40);
        int sectionTable = optional + optionalSize;
        writeSection(bytes, sectionTable, ".text", 0x180, 0x1000,
                RAW_SIZE, FIRST_RAW_OFFSET, 0x60000020L);
        writeSection(bytes, sectionTable + 40, ".custom", 0x180, 0x3000,
                RAW_SIZE, SECOND_RAW_OFFSET, 0xC0000040L);
        return new Fixture(bytes, optional, sectionTable, importEntry);
    }

    private static void writeSection(byte[] bytes, int offset, String name, long virtualSize,
                                     long rva, long rawSize, long rawOffset, long flags) {
        writeName(bytes, offset, name);
        put32(bytes, offset + 8, virtualSize);
        put32(bytes, offset + 12, rva);
        put32(bytes, offset + 16, rawSize);
        put32(bytes, offset + 20, rawOffset);
        put32(bytes, offset + 36, flags);
    }

    private static void writeName(byte[] bytes, int offset, String name) {
        byte[] encoded = name.getBytes(StandardCharsets.US_ASCII);
        check(encoded.length <= 8, "Section name fixture length");
        for (int index = 0; index < 8; index++) {
            bytes[offset + index] = index < encoded.length ? encoded[index] : 0;
        }
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

    private record Fixture(byte[] bytes, int optionalOffset, int sectionTableOffset,
                           int importEntryOffset) {
    }

    @FunctionalInterface
    private interface CheckedTest {
        void execute() throws Exception;
    }
}

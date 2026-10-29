package com.nikita.stage4;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class PeImportParserTest {
    private static final int PE_OFFSET = 0x80;
    private static final int HEADERS_SIZE = 0x200;
    private static final int FILE_SIZE = 0x2200;
    private static final long SECTION_RVA = 0x1000;
    private static final int RAW_OFFSET = 0x200;
    private static final int RAW_SIZE = 0x2000;
    private static final long DESCRIPTOR_RVA = 0x1040;
    private static final long DLL_NAME_RVA = 0x1200;
    private static final long LOOKUP_RVA = 0x1300;
    private static final long IAT_RVA = 0x1400;
    private static final long HINT_NAME_RVA = 0x1500;
    private static final String DLL_NAME = "IPHLPAPI.dll";
    private static final String FUNCTION_NAME = "GetAdaptersAddresses";
    private static final int HINT = 17;
    private static final int ORDINAL = 77;

    private final PeImportParser parser = new PeImportParser();
    private final Path directory;
    private final List<Path> ownFiles = new ArrayList<>();
    private int completedTests;

    private PeImportParserTest(Path directory) {
        this.directory = directory;
    }

    public static void main(String[] arguments) throws Exception {
        Path directory = Files.createTempDirectory("pe-stage4-tests-");
        PeImportParserTest suite = new PeImportParserTest(directory);
        try {
            suite.runAll();
            System.out.println("OK: " + suite.completedTests + " stage 4 tests passed.");
        } finally {
            for (Path path : suite.ownFiles) {
                Files.deleteIfExists(path);
            }
            Files.deleteIfExists(directory);
        }
    }

    private void runAll() throws Exception {
        run("PE32 named and ordinal symbols retain source addresses", () -> {
            Fixture fixture = fixture(false);
            PeImports imports = parse("пример PE32.exe", fixture);
            check(imports.image().headers().format() == PeFormat.PE32, "PE32 layout");
            check(imports.libraries().size() == 1, "One library");
            check(imports.symbolCount() == 2, "Two symbols");
            ImportedLibrary library = imports.libraries().get(0);
            check(library.name().equals(DLL_NAME), "DLL name");
            check(library.descriptorRva() == DESCRIPTOR_RVA, "Descriptor RVA");
            check(library.descriptorOffset() == raw(DESCRIPTOR_RVA), "Descriptor file offset");
            check(library.nameRva() == DLL_NAME_RVA, "DLL name RVA");
            check(library.originalFirstThunk() == LOOKUP_RVA, "Lookup RVA");
            check(library.firstThunk() == IAT_RVA, "IAT RVA");
            ImportedSymbol named = library.symbols().get(0);
            check(named.name().orElseThrow().equals(FUNCTION_NAME), "Function name");
            check(named.displayName().equals(FUNCTION_NAME), "Named display");
            check(!named.isByOrdinal(), "Named import flag");
            check(named.ordinal().isEmpty(), "No ordinal for named import");
            check(named.hint().orElseThrow() == HINT, "Hint");
            check(named.lookupRva() == LOOKUP_RVA, "Named lookup cell RVA");
            check(named.iatRva() == IAT_RVA, "Named IAT cell RVA");
            ImportedSymbol ordinal = library.symbols().get(1);
            check(ordinal.isByOrdinal(), "Ordinal import flag");
            check(ordinal.ordinal().orElseThrow() == ORDINAL, "Ordinal value");
            check(ordinal.name().isEmpty() && ordinal.hint().isEmpty(), "Ordinal has no name or hint");
            check(ordinal.lookupRva() == LOOKUP_RVA + 4, "PE32 lookup stride");
            check(ordinal.iatRva() == IAT_RVA + 4, "PE32 IAT stride");
        });

        run("PE32+ uses 8-byte cells and a 64-bit ordinal flag", () -> {
            PeImports imports = parse("pe32-plus.exe", fixture(true));
            check(imports.image().headers().format() == PeFormat.PE32_PLUS, "PE32+ layout");
            ImportedLibrary library = imports.libraries().get(0);
            check(library.symbols().size() == 2, "PE32+ symbol count");
            check(library.symbols().get(0).name().orElseThrow().equals(FUNCTION_NAME), "PE32+ name");
            ImportedSymbol ordinal = library.symbols().get(1);
            check(ordinal.ordinal().orElseThrow() == ORDINAL, "High-bit ordinal value");
            check(ordinal.lookupRva() == LOOKUP_RVA + 8, "PE32+ lookup stride");
            check(ordinal.iatRva() == IAT_RVA + 8, "PE32+ IAT stride");
            check(ordinal.displayName().contains(Integer.toString(ORDINAL)), "Ordinal display");
        });

        run("Multiple descriptors preserve library and symbol order", () -> {
            Fixture fixture = fixture(true);
            addSecondLibrary(fixture);
            PeImports imports = parse("two-libraries.exe", fixture);
            check(imports.libraries().size() == 2, "Two DLLs");
            check(imports.symbolCount() == 3, "All symbols counted");
            check(imports.libraries().get(0).name().equals(DLL_NAME), "First DLL");
            ImportedLibrary second = imports.libraries().get(1);
            check(second.name().equals("NETAPI32.dll"), "Second DLL");
            check(second.descriptorRva() == DESCRIPTOR_RVA + 20, "Descriptor stride");
            check(second.symbols().get(0).name().orElseThrow().equals("NetApiBufferFree"),
                    "Second DLL function");
        });

        run("A directory size need not be divisible by 20", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.directoryOffset() + 4, 41);
            check(parse("directory-size-41.exe", fixture).libraries().size() == 1,
                    "A complete zero descriptor is inside the declared range");
        });

        run("Names preserve spelling, case and C++ decorations", () -> {
            Fixture fixture = fixture(true);
            String decorated = "?Example@Widget@@QEAAHXZ";
            putString(fixture.bytes(), raw(DLL_NAME_RVA), "MixedCase.DlL");
            putString(fixture.bytes(), raw(HINT_NAME_RVA) + 2, decorated);
            ImportedLibrary library = parse("decorated.exe", fixture).libraries().get(0);
            check(library.name().equals("MixedCase.DlL"), "DLL spelling is preserved");
            check(library.symbols().get(0).name().orElseThrow().equals(decorated),
                    "Do not undecorate or normalize imported names");
        });

        run("A missing import directory slot produces an empty result", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.optionalOffset() + 92, 1);
            PeImports imports = parse("missing-slot.exe", fixture);
            check(imports.libraries().isEmpty() && imports.symbolCount() == 0, "No import slot");
        });

        run("A zero import directory produces an empty result", () -> {
            Fixture fixture = fixture(true);
            put32(fixture.bytes(), fixture.directoryOffset(), 0);
            put32(fixture.bytes(), fixture.directoryOffset() + 4, 0);
            PeImports imports = parse("no-imports.exe", fixture);
            check(imports.libraries().isEmpty() && imports.symbolCount() == 0, "Zero directory");
        });

        run("An all-zero first descriptor terminates an empty table", () -> {
            Fixture fixture = fixture(false);
            Arrays.fill(fixture.bytes(), raw(DESCRIPTOR_RVA), raw(DESCRIPTOR_RVA) + 20, (byte) 0);
            put32(fixture.bytes(), fixture.directoryOffset() + 4, 20);
            check(parse("empty-table.exe", fixture).libraries().isEmpty(), "Empty descriptor table");
        });

        run("OFT zero falls back to FirstThunk without terminating the descriptor array", () -> {
            Fixture fixture = fixture(true);
            put32(fixture.bytes(), raw(DESCRIPTOR_RVA), 0);
            PeImports imports = parse("iat-fallback.exe", fixture);
            check(imports.libraries().size() == 1 && imports.symbolCount() == 2, "Fallback parsed");
            ImportedLibrary library = imports.libraries().get(0);
            check(library.originalFirstThunk() == 0, "Preserve original descriptor");
            check(library.symbols().get(0).lookupRva() == IAT_RVA, "Fallback lookup cell");
            check(library.symbols().get(0).name().orElseThrow().equals(FUNCTION_NAME), "Fallback name");
        });

        run("Bound imports require a lookup table to recover names reliably", () -> {
            Fixture unsupported = fixture(true);
            put32(unsupported.bytes(), raw(DESCRIPTOR_RVA), 0);
            put32(unsupported.bytes(), raw(DESCRIPTOR_RVA) + 4, 0xFFFFFFFFL);
            expectInvalid("bound-without-lookup.exe", unsupported);
            Fixture supported = fixture(true);
            put32(supported.bytes(), raw(DESCRIPTOR_RVA) + 4, 0x12345678);
            put64(supported.bytes(), raw(IAT_RVA), 0x00007FF812345678L);
            check(parse("bound-with-lookup.exe", supported).symbolCount() == 2,
                    "Use the lookup table rather than bound IAT contents");
        });

        run("Nonnull descriptors need a DLL name and FirstThunk", () -> {
            Fixture missingName = fixture(false);
            put32(missingName.bytes(), raw(DESCRIPTOR_RVA) + 12, 0);
            expectInvalid("missing-dll-name.exe", missingName);
            Fixture missingIat = fixture(false);
            put32(missingIat.bytes(), raw(DESCRIPTOR_RVA) + 16, 0);
            expectInvalid("missing-iat.exe", missingIat);
            Fixture partial = fixture(false);
            put32(partial.bytes(), raw(DESCRIPTOR_RVA) + 20 + 8, 1);
            expectInvalid("partial-zero-descriptor.exe", partial);
        });

        run("The descriptor terminator must fit within Directory.Size", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.directoryOffset() + 4, 20);
            expectInvalid("missing-descriptor-terminator.exe", fixture);
        });

        run("An unterminated lookup table is rejected at the raw boundary", () -> {
            Fixture fixture = fixture(true);
            long lastTwoCells = SECTION_RVA + RAW_SIZE - 16;
            put32(fixture.bytes(), raw(DESCRIPTOR_RVA), lastTwoCells);
            put64(fixture.bytes(), raw(lastTwoCells), HINT_NAME_RVA);
            put64(fixture.bytes(), raw(lastTwoCells) + 8, ordinalFlag(true) | ORDINAL);
            expectInvalid("unterminated-thunks.exe", fixture);
        });

        run("A zero first lookup cell represents a library with no symbols", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), raw(LOOKUP_RVA), 0);
            PeImports imports = parse("empty-lookup.exe", fixture);
            check(imports.libraries().size() == 1 && imports.symbolCount() == 0, "Empty lookup");
        });

        run("A lookup table in a virtual-only tail cannot be read from disk", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), fixture.sectionOffset() + 8, 0x2800);
            put32(fixture.bytes(), raw(DESCRIPTOR_RVA), 0x3100);
            expectInvalid("lookup-in-virtual-tail.exe", fixture);
        });

        run("A DLL name RVA in an unmapped gap is rejected", () -> {
            Fixture fixture = fixture(true);
            put32(fixture.bytes(), raw(DESCRIPTOR_RVA) + 12, 0x9000);
            expectInvalid("dll-name-unmapped.exe", fixture);
        });

        run("A DLL name may end at the last raw byte but must have its terminator", () -> {
            Fixture valid = fixture(false);
            long nameRva = SECTION_RVA + RAW_SIZE - 8;
            put32(valid.bytes(), raw(DESCRIPTOR_RVA) + 12, nameRva);
            putString(valid.bytes(), raw(nameRva), "K32.dll");
            check(parse("dll-at-boundary.exe", valid).libraries().get(0).name().equals("K32.dll"),
                    "Include a terminator in the last available byte");
            Fixture invalid = fixture(false);
            put32(invalid.bytes(), raw(DESCRIPTOR_RVA) + 12, nameRva);
            Arrays.fill(invalid.bytes(), raw(nameRva), FILE_SIZE, (byte) 'A');
            expectInvalid("dll-without-terminator.exe", invalid);
        });

        run("Function names and hints cannot cross the raw boundary", () -> {
            Fixture missingTerminator = fixture(true);
            long nearEnd = SECTION_RVA + RAW_SIZE - 16;
            put64(missingTerminator.bytes(), raw(LOOKUP_RVA), nearEnd);
            put16(missingTerminator.bytes(), raw(nearEnd), HINT);
            Arrays.fill(missingTerminator.bytes(), raw(nearEnd) + 2, FILE_SIZE, (byte) 'A');
            expectInvalid("function-without-terminator.exe", missingTerminator);
            Fixture truncatedHint = fixture(true);
            put64(truncatedHint.bytes(), raw(LOOKUP_RVA), SECTION_RVA + RAW_SIZE - 1);
            expectInvalid("truncated-hint.exe", truncatedHint);
        });

        run("Empty DLL and function names are rejected", () -> {
            Fixture emptyDll = fixture(false);
            emptyDll.bytes()[raw(DLL_NAME_RVA)] = 0;
            expectInvalid("empty-dll-name.exe", emptyDll);
            Fixture emptyFunction = fixture(false);
            emptyFunction.bytes()[raw(HINT_NAME_RVA) + 2] = 0;
            expectInvalid("empty-function-name.exe", emptyFunction);
        });

        run("Non-ASCII DLL and function names are not silently replaced", () -> {
            Fixture invalidDll = fixture(false);
            invalidDll.bytes()[raw(DLL_NAME_RVA)] = (byte) 0x80;
            expectInvalid("non-ascii-dll.exe", invalidDll);
            Fixture invalidFunction = fixture(false);
            invalidFunction.bytes()[raw(HINT_NAME_RVA) + 2] = (byte) 0xFF;
            expectInvalid("non-ascii-function.exe", invalidFunction);
        });

        run("PE32+ named thunks reject nonzero reserved upper bits", () -> {
            Fixture fixture = fixture(true);
            put64(fixture.bytes(), raw(LOOKUP_RVA), (1L << 32) | HINT_NAME_RVA);
            expectInvalid("named-thunk-upper-bits.exe", fixture);
        });

        run("Ordinal thunks reject reserved bits in both formats", () -> {
            for (boolean plus : new boolean[] {false, true}) {
                Fixture fixture = fixture(plus);
                putThunk(fixture, raw(LOOKUP_RVA) + stride(plus),
                        ordinalFlag(plus) | 0x10000 | ORDINAL);
                expectInvalid(plus ? "ordinal-reserved-64.exe" : "ordinal-reserved-32.exe", fixture);
            }
        });

        run("An existing lookup table permits an IAT in zero-filled virtual storage", () -> {
            Fixture fixture = fixture(true);
            put32(fixture.bytes(), fixture.sectionOffset() + 8, 0x2800);
            put32(fixture.bytes(), raw(DESCRIPTOR_RVA) + 16, 0x3100);
            ImportedLibrary library = parse("iat-virtual-storage.exe", fixture).libraries().get(0);
            check(library.symbols().size() == 2, "The IAT contents are not needed to read names");
            check(library.symbols().get(0).iatRva() == 0x3100, "First IAT cell");
            check(library.symbols().get(1).iatRva() == 0x3108, "Second IAT cell");
        });

        run("IAT cell arithmetic must remain inside the 32-bit RVA space", () -> {
            Fixture fixture = fixture(true);
            put32(fixture.bytes(), raw(DESCRIPTOR_RVA) + 16, 0xFFFFFFFCL);
            expectInvalid("iat-cell-overflow.exe", fixture);
        });

        run("An unmapped lookup table RVA is rejected", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), raw(DESCRIPTOR_RVA), 0x9000);
            expectInvalid("unmapped-lookup.exe", fixture);
        });

        run("Library and symbol lists are immutable snapshots", () -> {
            PeImports imports = parse("immutable-result.exe", fixture(false));
            expectImmutable(() -> imports.libraries().clear());
            expectImmutable(() -> imports.libraries().get(0).symbols().clear());
        });

        run("Names without a terminator within the configured length limit are rejected", () -> {
            Fixture fixture = fixture(false);
            Arrays.fill(fixture.bytes(), raw(DLL_NAME_RVA), raw(DLL_NAME_RVA) + 4097, (byte) 'A');
            expectInvalid("name-limit.exe", fixture);
        });

        run("Lookup and Hint-Name data may be outside the descriptor directory size", () -> {
            Fixture fixture = fixture(true);
            int descriptorEnd = raw(DESCRIPTOR_RVA) + 40;
            check(raw(DLL_NAME_RVA) > descriptorEnd, "DLL name is outside descriptor range");
            check(raw(LOOKUP_RVA) > descriptorEnd, "Lookup is outside descriptor range");
            check(raw(HINT_NAME_RVA) > descriptorEnd, "Hint-Name is outside descriptor range");
            check(parse("separate-import-data.exe", fixture).symbolCount() == 2,
                    "Directory.Size does not enclose every referenced string and table");
        });

        run("The complete unsigned 16-bit ordinal range is retained", () -> {
            for (int ordinal : new int[] {0, 65535}) {
                Fixture fixture = fixture(true);
                put64(fixture.bytes(), raw(LOOKUP_RVA) + 8, ordinalFlag(true) | ordinal);
                ImportedSymbol symbol = parse("ordinal-" + ordinal + ".exe", fixture)
                        .libraries().get(0).symbols().get(1);
                check(symbol.ordinal().orElseThrow() == ordinal, "Unsigned ordinal");
            }
        });

        run("A referenced DLL name can be stored in the mapped headers", () -> {
            Fixture fixture = fixture(false);
            put32(fixture.bytes(), raw(DESCRIPTOR_RVA) + 12, 0x60);
            putString(fixture.bytes(), 0x60, DLL_NAME);
            ImportedLibrary library = parse("name-in-headers.exe", fixture).libraries().get(0);
            check(library.name().equals(DLL_NAME) && library.nameRva() == 0x60,
                    "Header RVA uses the same file offset");
        });
    }

    private PeImports parse(String name, Fixture fixture) throws IOException, PeFormatException {
        Path path = directory.resolve(name);
        ownFiles.add(path);
        Files.write(path, fixture.bytes());
        return parser.parse(path);
    }

    private void expectInvalid(String name, Fixture fixture) throws IOException, PeFormatException {
        try {
            parse(name, fixture);
            throw new AssertionError("Expected PeFormatException for " + name);
        } catch (PeFormatException expected) {
            check(expected.getMessage() != null && !expected.getMessage().isBlank(),
                    "Invalid input needs an explanatory message");
        }
    }

    private static void expectImmutable(Runnable operation) {
        try {
            operation.run();
            throw new AssertionError("Expected an immutable result list");
        } catch (UnsupportedOperationException expected) {
            // Expected for immutable snapshots.
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
        byte[] bytes = new byte[FILE_SIZE];
        bytes[0] = 'M';
        bytes[1] = 'Z';
        put32(bytes, 0x3C, PE_OFFSET);
        bytes[PE_OFFSET] = 'P';
        bytes[PE_OFFSET + 1] = 'E';
        int coff = PE_OFFSET + 4;
        put16(bytes, coff, plus ? 0x8664 : 0x14C);
        put16(bytes, coff + 2, 1);
        int optionalSize = plus ? 240 : 224;
        put16(bytes, coff + 16, optionalSize);
        put16(bytes, coff + 18, plus ? 0x22 : 0x102);
        int optional = coff + 20;
        put16(bytes, optional, plus ? 0x20B : 0x10B);
        put32(bytes, optional + 16, 0x1100);
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
        int directory = optional + (plus ? 112 : 96) + 8;
        put32(bytes, directory, DESCRIPTOR_RVA);
        put32(bytes, directory + 4, 40);
        int section = optional + optionalSize;
        byte[] sectionName = ".custom".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(sectionName, 0, bytes, section, sectionName.length);
        put32(bytes, section + 8, RAW_SIZE);
        put32(bytes, section + 12, SECTION_RVA);
        put32(bytes, section + 16, RAW_SIZE);
        put32(bytes, section + 20, RAW_OFFSET);
        put32(bytes, section + 36, 0x40000040L);
        writeDescriptor(bytes, raw(DESCRIPTOR_RVA), LOOKUP_RVA, DLL_NAME_RVA, IAT_RVA);
        putString(bytes, raw(DLL_NAME_RVA), DLL_NAME);
        put16(bytes, raw(HINT_NAME_RVA), HINT);
        putString(bytes, raw(HINT_NAME_RVA) + 2, FUNCTION_NAME);
        Fixture fixture = new Fixture(bytes, plus, optional, section, directory);
        for (long tableRva : new long[] {LOOKUP_RVA, IAT_RVA}) {
            putThunk(fixture, raw(tableRva), HINT_NAME_RVA);
            putThunk(fixture, raw(tableRva) + stride(plus), ordinalFlag(plus) | ORDINAL);
        }
        return fixture;
    }

    private static void addSecondLibrary(Fixture fixture) {
        byte[] bytes = fixture.bytes();
        put32(bytes, fixture.directoryOffset() + 4, 60);
        writeDescriptor(bytes, raw(DESCRIPTOR_RVA) + 20, 0x1700, 0x1600, 0x1800);
        putString(bytes, raw(0x1600), "NETAPI32.dll");
        put16(bytes, raw(0x1900), 9);
        putString(bytes, raw(0x1900) + 2, "NetApiBufferFree");
        putThunk(fixture, raw(0x1700), 0x1900);
        putThunk(fixture, raw(0x1800), 0x1900);
    }

    private static void writeDescriptor(byte[] bytes, int offset, long oft, long name, long ft) {
        put32(bytes, offset, oft);
        put32(bytes, offset + 4, 0);
        put32(bytes, offset + 8, 0);
        put32(bytes, offset + 12, name);
        put32(bytes, offset + 16, ft);
    }

    private static int raw(long rva) {
        return Math.toIntExact(RAW_OFFSET + rva - SECTION_RVA);
    }

    private static int stride(boolean plus) {
        return plus ? 8 : 4;
    }

    private static long ordinalFlag(boolean plus) {
        return plus ? Long.MIN_VALUE : 0x80000000L;
    }

    private static void putThunk(Fixture fixture, int offset, long value) {
        if (fixture.plus()) {
            put64(fixture.bytes(), offset, value);
        } else {
            put32(fixture.bytes(), offset, value);
        }
    }

    private static void putString(byte[] bytes, int offset, String text) {
        byte[] encoded = text.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(encoded, 0, bytes, offset, encoded.length);
        bytes[offset + encoded.length] = 0;
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

    private record Fixture(byte[] bytes, boolean plus, int optionalOffset,
                           int sectionOffset, int directoryOffset) {
    }

    @FunctionalInterface
    private interface CheckedTest {
        void execute() throws Exception;
    }
}

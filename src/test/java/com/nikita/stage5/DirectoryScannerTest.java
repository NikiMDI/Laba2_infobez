package com.nikita.stage5;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class DirectoryScannerTest {
    private static final int PE_OFFSET = 0x80;
    private static final int SECTION_RVA = 0x1000;
    private static final int RAW_OFFSET = 0x200;
    private static final int LOOKUP_RVA = 0x1140;
    private static final int IAT_RVA = 0x1180;
    private final DirectoryScanner scanner = new DirectoryScanner();
    private final Path workspace;
    private int completedTests;

    private DirectoryScannerTest(Path workspace) {
        this.workspace = workspace;
    }

    public static void main(String[] args) throws Exception {
        Path workspace = Files.createTempDirectory("pe-stage5-directory-tests-");
        DirectoryScannerTest tests = new DirectoryScannerTest(workspace);
        try {
            tests.runAll();
            System.out.printf("OK: %d stage 5 directory tests passed.%n", tests.completedTests);
        } finally {
            List<Path> paths;
            try (var stream = Files.walk(workspace)) {
                paths = stream.sorted(Comparator.reverseOrder()).toList();
            }
            for (Path path : paths) {
                Files.deleteIfExists(path);
            }
        }
    }

    private void runAll() throws Exception {
        run("An empty directory is a successful empty scan", () -> {
            Path directory = directory("empty");
            DirectoryAnalysis result = scanner.scan(directory);
            check(result.directory().equals(directory.toAbsolutePath().normalize()), "Normalized directory");
            check(result.files().isEmpty() && result.failures().isEmpty(), "Empty result lists");
            check(result.skippedFileCount() == 0 && result.matchCount() == 0, "Zero counts");
            check(result.matchedFileCount() == 0 && !result.hasFailures(), "Successful empty scan");
        });

        run("A mixed directory detects both PE formats and skips plain text", () -> {
            Path directory = directory("mixed");
            write(directory.resolve("one.dll"), fixture(false, "NetApiBufferFree"));
            write(directory.resolve("two.exe"), fixture(true, "WNetGetUniversalNameW"));
            Files.writeString(directory.resolve("readme.txt"), "A text document", StandardCharsets.UTF_8);
            DirectoryAnalysis result = scanner.scan(directory);
            check(result.files().size() == 2 && result.failures().isEmpty(), "Both PE files parsed");
            check(result.matchCount() == 2 && result.matchedFileCount() == 2, "Both positives found");
            check(result.skippedFileCount() == 1, "Only text skipped");
            check(result.files().get(0).imports().image().headers().format() == PeFormat.PE32, "PE32 retained");
            check(result.files().get(1).imports().image().headers().format() == PeFormat.PE32_PLUS, "PE32+ retained");
        });

        run("Scanning descends into nested directories and handles Unicode paths", () -> {
            Path directory = directory("recursive");
            Path file = directory.resolve("вложенная папка/ещё глубже/пример.dll");
            write(file, fixture(true, "NetApiBufferFree"));
            DirectoryAnalysis result = scanner.scan(directory);
            check(result.files().size() == 1 && result.matchCount() == 1, "Nested file found");
            check(result.files().getFirst().imports().image().headers().path().equals(file), "Full source path");
        });

        run("PE detection includes renamed files and uppercase DLL suffixes", () -> {
            Path directory = directory("extensions");
            write(directory.resolve("renamed-data"), fixture(true, "NetApiBufferFree"));
            write(directory.resolve("UPPER.DLL"), fixture(false, "WNetGetUniversalNameW"));
            DirectoryAnalysis result = scanner.scan(directory);
            check(result.files().size() == 2 && result.matchCount() == 2, "Detect by bytes rather than suffix");
            check(result.skippedFileCount() == 0, "No extension-based skips");
        });

        run("Non-PE probes are skipped without becoming parse failures", () -> {
            Path directory = directory("non-pe");
            write(directory.resolve("short.dll"), new byte[] {'M', 'Z'});
            write(directory.resolve("long.txt"), new byte[128]);
            byte[] invalidOffset = new byte[128];
            invalidOffset[0] = 'M';
            invalidOffset[1] = 'Z';
            put32(invalidOffset, 0x3C, 0xFFFFFFF0L);
            write(directory.resolve("dos.exe"), invalidOffset);
            DirectoryAnalysis result = scanner.scan(directory);
            check(result.files().isEmpty() && !result.hasFailures(), "No false PE detection");
            check(result.skippedFileCount() == 3, "Every regular non-PE file counted");
        });

        run("Probe enforces DOS bounds and includes all four PE signature bytes", () -> {
            Path directory = directory("probe-bounds");
            byte[] insideDos = dosBytes(128, 32);
            insideDos[32] = 'P';
            insideDos[33] = 'E';
            write(directory.resolve("inside-dos.bin"), insideDos);
            byte[] truncated = dosBytes(128, 125);
            truncated[125] = 'P';
            truncated[126] = 'E';
            write(directory.resolve("truncated-signature.bin"), truncated);
            byte[] completeAtEnd = dosBytes(128, 124);
            completeAtEnd[124] = 'P';
            completeAtEnd[125] = 'E';
            Path recognized = directory.resolve("complete-signature-only.bin");
            write(recognized, completeAtEnd);
            DirectoryAnalysis result = scanner.scan(directory);
            check(result.files().isEmpty() && result.skippedFileCount() == 2, "Invalid signature ranges skipped");
            check(result.failures().size() == 1, "Complete PE signature proceeds to structural validation");
            check(result.failures().getFirst().path().equals(recognized), "Recognized truncated PE reported");
        });

        run("A malformed recognized PE is reported and does not stop other files", () -> {
            Path directory = directory("malformed");
            byte[] invalid = fixture(true, "NetApiBufferFree");
            put16(invalid, PE_OFFSET + 24, 0x7777);
            Path broken = directory.resolve("broken.dll");
            write(broken, invalid);
            write(directory.resolve("valid.dll"), fixture(false, "NetApiBufferFree"));
            DirectoryAnalysis result = scanner.scan(directory);
            check(result.files().size() == 1 && result.matchCount() == 1, "Good file survives");
            check(result.hasFailures() && result.failures().size() == 1, "Malformed PE reported");
            check(result.failures().getFirst().path().equals(broken), "Failure source path retained");
            check(!result.failures().getFirst().message().isBlank(), "Failure explains the reason");
            check(result.skippedFileCount() == 0, "Malformed recognized PE is not a non-PE skip");
        });

        run("A missing root directory throws NoSuchFileException", () -> {
            try {
                scanner.scan(workspace.resolve("never-created"));
                throw new AssertionError("Expected a missing-directory error");
            } catch (NoSuchFileException expected) {
                check(expected.getFile() != null, "Missing root identified");
            }
        });

        run("A regular file used as the root throws NotDirectoryException", () -> {
            Path file = workspace.resolve("root-file.dll");
            write(file, fixture(true, "NetApiBufferFree"));
            try {
                scanner.scan(file);
                throw new AssertionError("Expected a directory argument");
            } catch (NotDirectoryException expected) {
                check(expected.getFile() != null, "Incorrect root identified");
            }
        });

        run("Results are ordered deterministically by case-insensitive absolute path", () -> {
            Path directory = directory("ordering");
            List<Path> expected = new ArrayList<>();
            for (String name : List.of("zeta.dll", "Beta.dll", "alpha.dll")) {
                Path file = directory.resolve(name);
                write(file, fixture(true, "NetApiBufferFree"));
                expected.add(file);
            }
            expected.sort(Comparator.comparing(Path::toString, String.CASE_INSENSITIVE_ORDER)
                    .thenComparing(Path::toString));
            List<Path> actual = scanner.scan(directory).files().stream()
                    .map(result -> result.imports().image().headers().path()).toList();
            check(actual.equals(expected), "Independent of directory enumeration order");
        });

        run("Directory result lists are immutable independent snapshots", () -> {
            Path directory = directory("immutable");
            write(directory.resolve("valid.dll"), fixture(true, "NetApiBufferFree"));
            DirectoryAnalysis scan = scanner.scan(directory);
            List<NetworkAnalysis> files = new ArrayList<>(scan.files());
            List<ScanFailure> failures = new ArrayList<>();
            failures.add(new ScanFailure(directory.resolve("bad.dll"), "Expected test failure"));
            DirectoryAnalysis result = new DirectoryAnalysis(directory, files, failures, 0);
            files.clear();
            failures.clear();
            check(result.files().size() == 1 && result.failures().size() == 1, "Defensive list copies");
            expectImmutable(() -> result.files().clear());
            expectImmutable(() -> result.failures().clear());
        });

        run("Per-file matches retain symbol order, actual DLL and cell RVAs", () -> {
            Path directory = directory("evidence");
            write(directory.resolve("two-imports.dll"),
                    fixture(true, "WNetGetUniversalNameW", "NetApiBufferFree"));
            DirectoryAnalysis result = scanner.scan(directory);
            List<NetworkMatch> matches = result.files().getFirst().matches();
            check(result.matchedFileCount() == 1 && result.matchCount() == 2, "File and entry counts differ");
            check(matches.get(0).functionName().equals("WNetGetUniversalNameW"), "First symbol");
            check(matches.get(1).functionName().equals("NetApiBufferFree"), "Second symbol");
            check(matches.get(0).libraryName().equals("Example.DlL"), "Actual descriptor DLL");
            check(matches.get(0).lookupRva() == LOOKUP_RVA && matches.get(0).iatRva() == IAT_RVA,
                    "First symbol evidence");
            check(matches.get(1).lookupRva() == LOOKUP_RVA + 8 && matches.get(1).iatRva() == IAT_RVA + 8,
                    "Second symbol evidence");
        });

        run("A valid PE with no imports remains in the successfully analyzed files", () -> {
            Path directory = directory("no-imports");
            byte[] bytes = fixture(false, "NetApiBufferFree");
            int importDirectory = PE_OFFSET + 24 + 96 + 8;
            put32(bytes, importDirectory, 0);
            put32(bytes, importDirectory + 4, 0);
            write(directory.resolve("empty-imports.dll"), bytes);
            DirectoryAnalysis result = scanner.scan(directory);
            check(result.files().size() == 1 && !result.hasFailures(), "Valid PE analyzed");
            check(result.matchCount() == 0 && result.matchedFileCount() == 0, "Successful zero matches");
            check(result.skippedFileCount() == 0, "PE is not skipped");
        });
    }

    private Path directory(String name) throws IOException {
        return Files.createDirectories(workspace.resolve(name));
    }

    private static void write(Path file, byte[] bytes) throws IOException {
        Files.createDirectories(file.getParent());
        Files.write(file, bytes);
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

    private static void expectImmutable(Runnable operation) {
        try {
            operation.run();
            throw new AssertionError("Expected an immutable list");
        } catch (UnsupportedOperationException expected) {
            check(true, "Immutable result");
        }
    }

    private static byte[] fixture(boolean plus, String... names) {
        if (names.length > 2) {
            throw new IllegalArgumentException("Test fixture allows two names");
        }
        byte[] bytes = new byte[0x600];
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
        put16(bytes, coff + 18, 0x2022);
        int optional = coff + 20;
        put16(bytes, optional, plus ? 0x20B : 0x10B);
        if (plus) {
            put64(bytes, optional + 24, 0x140000000L);
        } else {
            put32(bytes, optional + 28, 0x400000);
        }
        put32(bytes, optional + 32, 0x1000);
        put32(bytes, optional + 36, 0x200);
        put32(bytes, optional + 56, 0x2000);
        put32(bytes, optional + 60, 0x200);
        put16(bytes, optional + 68, 3);
        put32(bytes, optional + (plus ? 108 : 92), 16);
        int directory = optional + (plus ? 112 : 96) + 8;
        put32(bytes, directory, 0x1040);
        put32(bytes, directory + 4, 40);
        int section = optional + optionalSize;
        putString(bytes, section, ".idata");
        put32(bytes, section + 8, 0x400);
        put32(bytes, section + 12, SECTION_RVA);
        put32(bytes, section + 16, 0x400);
        put32(bytes, section + 20, RAW_OFFSET);
        put32(bytes, section + 36, 0x40000040);
        int descriptor = raw(0x1040);
        put32(bytes, descriptor, LOOKUP_RVA);
        put32(bytes, descriptor + 12, 0x1100);
        put32(bytes, descriptor + 16, IAT_RVA);
        putString(bytes, raw(0x1100), "Example.DlL");
        int width = plus ? 8 : 4;
        for (int index = 0; index < names.length; index++) {
            int hintNameRva = 0x1200 + index * 0x40;
            put16(bytes, raw(hintNameRva), index);
            putString(bytes, raw(hintNameRva) + 2, names[index]);
            for (int table : new int[] {LOOKUP_RVA, IAT_RVA}) {
                if (plus) {
                    put64(bytes, raw(table) + index * width, hintNameRva);
                } else {
                    put32(bytes, raw(table) + index * width, hintNameRva);
                }
            }
        }
        return bytes;
    }

    private static byte[] dosBytes(int size, int peOffset) {
        byte[] bytes = new byte[size];
        bytes[0] = 'M';
        bytes[1] = 'Z';
        put32(bytes, 0x3C, peOffset);
        return bytes;
    }

    private static int raw(int rva) {
        return RAW_OFFSET + rva - SECTION_RVA;
    }

    private static void putString(byte[] bytes, int offset, String value) {
        byte[] text = value.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(text, 0, bytes, offset, text.length);
        bytes[offset + text.length] = 0;
    }

    private static void put16(byte[] bytes, int offset, int value) {
        for (int index = 0; index < 2; index++) {
            bytes[offset + index] = (byte) (value >>> (index * 8));
        }
    }

    private static void put32(byte[] bytes, int offset, long value) {
        for (int index = 0; index < 4; index++) {
            bytes[offset + index] = (byte) (value >>> (index * 8));
        }
    }

    private static void put64(byte[] bytes, int offset, long value) {
        for (int index = 0; index < 8; index++) {
            bytes[offset + index] = (byte) (value >>> (index * 8));
        }
    }

    @FunctionalInterface
    private interface CheckedTest {
        void execute() throws Exception;
    }
}

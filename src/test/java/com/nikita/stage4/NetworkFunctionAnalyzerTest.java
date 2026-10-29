package com.nikita.stage4;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

public final class NetworkFunctionAnalyzerTest {
    private final NetworkFunctionAnalyzer analyzer = new NetworkFunctionAnalyzer();
    private int completedTests;

    public static void main(String[] args) {
        NetworkFunctionAnalyzerTest tests = new NetworkFunctionAnalyzerTest();
        tests.runAll();
        System.out.printf("OK: %d stage 4 matching tests passed.%n", tests.completedTests);
    }

    private void runAll() {
        run("Catalog keeps the 176 literal assignment names", () -> {
            check(NetworkFunctionCatalog.size() == 176, "Distinct assignment names");
            check(NetworkFunctionCatalog.contains("IcmpCloseHandle"), "Repeated original name retained");
            check(NetworkFunctionCatalog.contains("NetapipBufferAllocate"), "Original spelling retained");
            check(NetworkFunctionCatalog.contains("WNetCloseEnumW"), "Original W variant retained");
        });

        run("A listed named import is found", () -> {
            NetworkAnalysis result = analyze(library("MPR.dll", named("WNetGetUniversalNameW", 0x1200, 0x2200)));
            check(result.hasMatches() && result.matches().size() == 1, "One exact match");
            check(result.namedImportCount() == 1 && result.ordinalImportCount() == 0, "Named count");
            check(result.matches().getFirst().functionName().equals("WNetGetUniversalNameW"), "Exact spelling");
        });

        run("Function matching is case sensitive", () -> {
            NetworkAnalysis result = analyze(library("NETAPI32.dll",
                    named("netapibufferfree", 0x1000, 0x2000),
                    named("NETAPIBUFFERFREE", 0x1008, 0x2008),
                    named("NetApiBufferFree", 0x1010, 0x2010)));
            check(result.matches().size() == 1, "Only literal case matches");
            check(result.namedImportCount() == 3, "Nonmatching names are still counted");
        });

        run("Missing A and W variants are not automatically added", () -> {
            NetworkAnalysis result = analyze(library("MPR.dll",
                    named("WNetGetUniversalNameA", 0x1000, 0x2000),
                    named("WNetGetUniversalNameW", 0x1008, 0x2008),
                    named("WNetGetUniversalName", 0x1010, 0x2010)));
            check(result.matches().size() == 2, "The unsuffixed and W names are explicitly listed");
            check(result.matches().stream().noneMatch(match -> match.functionName().endsWith("A")),
                    "Unlisted A variant must not match");
        });

        run("Only complete names match without substring or undecoration rules", () -> {
            NetworkAnalysis result = analyze(library("example.dll",
                    named("PrefixNetApiBufferFree", 0x1000, 0x2000),
                    named("NetApiBufferFreeSuffix", 0x1008, 0x2008),
                    named("_NetApiBufferFree@4", 0x1010, 0x2010),
                    named("?NetApiBufferFree@@YAXXZ", 0x1018, 0x2018)));
            check(!result.hasMatches() && result.matches().isEmpty(), "No approximate matching");
        });

        run("Matching does not filter DLL names and preserves their spelling", () -> {
            NetworkAnalysis result = analyze(library("Unusual.Library.DlL", named("NetApiBufferFree", 0x1000, 0x2000)));
            check(result.matches().getFirst().libraryName().equals("Unusual.Library.DlL"),
                    "Use the descriptor DLL name literally");
        });

        run("Ordinal imports are counted and skipped", () -> {
            NetworkAnalysis result = analyze(library("NETAPI32.dll",
                    ordinal(0, 0x1000, 0x2000),
                    named("NetApiBufferFree", 0x1008, 0x2008),
                    ordinal(65535, 0x1010, 0x2010)));
            check(result.ordinalImportCount() == 2 && result.namedImportCount() == 1, "Separate counts");
            check(result.matches().size() == 1, "Only the named import matches");
        });

        run("No imported libraries is a valid empty result", () -> {
            NetworkAnalysis result = analyze();
            check(!result.hasMatches() && result.matches().isEmpty(), "Empty matches");
            check(result.namedImportCount() == 0 && result.ordinalImportCount() == 0, "Zero counts");
        });

        run("Libraries with zero symbols do not create matches", () -> {
            NetworkAnalysis result = analyze(library("MPR.dll"), library("NETAPI32.dll"));
            check(result.imports().libraries().size() == 2, "Keep imported libraries");
            check(!result.hasMatches() && result.namedImportCount() == 0, "No invented symbols");
        });

        run("A valid list of unrelated named imports produces zero matches", () -> {
            NetworkAnalysis result = analyze(library("KERNEL32.dll",
                    named("SetUnhandledExceptionFilter", 0x1000, 0x2000),
                    named("GetProcAddress", 0x1008, 0x2008)));
            check(!result.hasMatches(), "Unlisted functions are excluded");
            check(result.namedImportCount() == 2 && result.imports().symbolCount() == 2, "All imports retained");
        });

        run("Repeated imports retain the library and symbol order", () -> {
            NetworkAnalysis result = analyze(
                    library("First.dll", named("NetApiBufferFree", 0x1000, 0x2000),
                            named("WNetGetUniversalNameW", 0x1008, 0x2008),
                            named("NetApiBufferFree", 0x1010, 0x2010)),
                    library("Second.dll", named("NetApiBufferFree", 0x3000, 0x4000)));
            check(result.matches().size() == 4, "Count matching import entries rather than unique names");
            check(result.matches().get(0).functionName().equals("NetApiBufferFree"), "First symbol");
            check(result.matches().get(1).functionName().equals("WNetGetUniversalNameW"), "Second symbol");
            check(result.matches().get(2).lookupRva() == 0x1010, "Repeated symbol preserved");
            check(result.matches().get(3).libraryName().equals("Second.dll"), "Next library follows");
        });

        run("Match evidence retains both cell RVAs and the source imports", () -> {
            PeImports imports = imports(PeFormat.PE32_PLUS,
                    library("MPR.dll", named("WNetGetUniversalNameW", 0x12345678, 0x23456789)));
            NetworkAnalysis result = analyzer.findMatches(imports);
            NetworkMatch match = result.matches().getFirst();
            check(result.imports() == imports, "Keep the parsed source snapshot");
            check(match.lookupRva() == 0x12345678 && match.iatRva() == 0x23456789, "Unmodified evidence");
        });

        run("Analysis matches form an immutable independent snapshot", () -> {
            PeImports imports = imports(PeFormat.PE32_PLUS,
                    library("NETAPI32.dll", named("NetApiBufferFree", 0x1000, 0x2000)));
            List<NetworkMatch> mutable = new ArrayList<>(analyzer.findMatches(imports).matches());
            NetworkAnalysis result = new NetworkAnalysis(imports, mutable, 0);
            mutable.clear();
            check(result.matches().size() == 1, "Defensive copy");
            try {
                result.matches().clear();
                throw new AssertionError("Matches must be immutable");
            } catch (UnsupportedOperationException expected) {
                check(result.hasMatches(), "Failed mutation does not alter the result");
            }
        });

        run("Matching works equally for parsed PE32 and PE32+ data", () -> {
            for (PeFormat format : PeFormat.values()) {
                NetworkAnalysis result = analyzer.findMatches(imports(format,
                        library("IPHLPAPI.dll", named("GetAdaptersAddresses", 0x1000, 0x2000))));
                check(result.hasMatches() && result.matches().size() == 1, "Format-independent matching");
                check(result.imports().image().headers().format() == format, "Format retained");
            }
        });
    }

    private NetworkAnalysis analyze(ImportedLibrary... libraries) {
        return analyzer.findMatches(imports(PeFormat.PE32_PLUS, libraries));
    }

    private static PeImports imports(PeFormat format, ImportedLibrary... libraries) {
        PeHeaders headers = new PeHeaders(Path.of("matching-fixture.exe"), 4096, 0x80,
                format == PeFormat.PE32 ? 0x14C : 0x8664, 0,
                format == PeFormat.PE32 ? 224 : 240, format, 0,
                format == PeFormat.PE32 ? 0x400000L : 0x140000000L,
                0x5000, 0x200, 16, 0x200, 0x22, 3);
        PeImage image = new PeImage(headers, List.of(), Optional.empty());
        return new PeImports(image, List.of(libraries));
    }

    private static ImportedLibrary library(String name, ImportedSymbol... symbols) {
        return new ImportedLibrary(name, 0x1000, 0x200, 0x1100, 0x1200, 0x2200, List.of(symbols));
    }

    private static ImportedSymbol named(String name, long lookup, long iat) {
        return new ImportedSymbol(Optional.of(name), OptionalInt.empty(), OptionalInt.of(0), lookup, iat);
    }

    private static ImportedSymbol ordinal(int value, long lookup, long iat) {
        return new ImportedSymbol(Optional.empty(), OptionalInt.of(value), OptionalInt.empty(), lookup, iat);
    }

    private void run(String name, Runnable test) {
        try {
            test.run();
            completedTests++;
        } catch (RuntimeException | AssertionError failure) {
            throw new AssertionError("Test failed: " + name, failure);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

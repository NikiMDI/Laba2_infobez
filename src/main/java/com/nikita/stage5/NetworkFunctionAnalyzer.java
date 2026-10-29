package com.nikita.stage5;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class NetworkFunctionAnalyzer {
    public NetworkAnalysis analyze(Path path) throws IOException, PeFormatException {
        PeImports imports = new PeImportParser().parse(path);
        return findMatches(imports);
    }

    NetworkAnalysis findMatches(PeImports imports) {
        Objects.requireNonNull(imports, "imports");
        List<NetworkMatch> matches = new ArrayList<>();
        int ordinalImportCount = 0;

        for (ImportedLibrary library : imports.libraries()) {
            for (ImportedSymbol symbol : library.symbols()) {
                if (symbol.isByOrdinal()) {
                    ordinalImportCount++;
                    continue;
                }

                String name = symbol.name().orElseThrow();
                if (NetworkFunctionCatalog.contains(name)) {
                    matches.add(new NetworkMatch(library.name(), name,
                            symbol.lookupRva(), symbol.iatRva()));
                }
            }
        }

        return new NetworkAnalysis(imports, matches, ordinalImportCount);
    }
}

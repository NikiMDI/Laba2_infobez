package com.nikita.stage5;

import java.util.List;
import java.util.Objects;

public record NetworkAnalysis(
        PeImports imports,
        List<NetworkMatch> matches,
        int ordinalImportCount) {

    public NetworkAnalysis {
        Objects.requireNonNull(imports, "imports");
        matches = List.copyOf(matches);
        if (ordinalImportCount < 0 || ordinalImportCount > imports.symbolCount()) {
            throw new IllegalArgumentException("Некорректное число импортов по ordinal");
        }
    }

    public boolean hasMatches() {
        return !matches.isEmpty();
    }

    public int namedImportCount() {
        return imports.symbolCount() - ordinalImportCount;
    }
}

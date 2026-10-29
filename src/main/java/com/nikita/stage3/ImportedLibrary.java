package com.nikita.stage3;

import java.util.List;
import java.util.Objects;

public record ImportedLibrary(
        String name,
        long descriptorRva,
        long descriptorOffset,
        long nameRva,
        long originalFirstThunk,
        long firstThunk,
        List<ImportedSymbol> symbols) {

    public ImportedLibrary {
        Objects.requireNonNull(name, "name");
        symbols = List.copyOf(symbols);
    }
}

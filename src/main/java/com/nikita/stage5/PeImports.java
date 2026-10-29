package com.nikita.stage5;

import java.util.List;
import java.util.Objects;

public record PeImports(PeImage image, List<ImportedLibrary> libraries) {
    public PeImports {
        Objects.requireNonNull(image, "image");
        libraries = List.copyOf(libraries);
    }

    public int symbolCount() {
        return libraries.stream().mapToInt(library -> library.symbols().size()).sum();
    }
}

package com.nikita.stage3;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record PeImage(
        PeHeaders headers,
        List<PeSection> sections,
        Optional<PeDataDirectory> importDirectory) {

    public PeImage {
        Objects.requireNonNull(headers, "headers");
        sections = List.copyOf(sections);
        Objects.requireNonNull(importDirectory, "importDirectory");
    }
}

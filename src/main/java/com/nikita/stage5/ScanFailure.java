package com.nikita.stage5;

import java.nio.file.Path;
import java.util.Objects;

public record ScanFailure(Path path, String message) {
    public ScanFailure {
        path = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        Objects.requireNonNull(message, "message");
    }
}

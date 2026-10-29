package com.nikita.stage5;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

public record DirectoryAnalysis(
        Path directory,
        List<NetworkAnalysis> files,
        List<ScanFailure> failures,
        int skippedFileCount) {

    public DirectoryAnalysis {
        directory = Objects.requireNonNull(directory, "directory").toAbsolutePath().normalize();
        files = List.copyOf(files);
        failures = List.copyOf(failures);
        if (skippedFileCount < 0) {
            throw new IllegalArgumentException("Число пропущенных файлов не может быть отрицательным");
        }
    }

    public long matchedFileCount() {
        return files.stream().filter(NetworkAnalysis::hasMatches).count();
    }

    public long matchCount() {
        return files.stream().mapToLong(file -> file.matches().size()).sum();
    }

    public boolean hasFailures() {
        return !failures.isEmpty();
    }
}

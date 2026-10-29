package com.nikita.stage5;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class DirectoryScanner {
    public DirectoryAnalysis scan(Path directory) throws IOException {
        Path root = directory.toAbsolutePath().normalize();
        BasicFileAttributes attributes = Files.readAttributes(
                root, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isDirectory()) {
            throw new NotDirectoryException(root.toString());
        }

        NetworkFunctionAnalyzer analyzer = new NetworkFunctionAnalyzer();
        List<NetworkAnalysis> files = new ArrayList<>();
        List<ScanFailure> failures = new ArrayList<>();
        int[] skipped = {0};

        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (!attrs.isRegularFile()) {
                    return FileVisitResult.CONTINUE;
                }
                try {
                    if (hasPeSignature(file)) {
                        files.add(analyzer.analyze(file));
                    } else {
                        skipped[0]++;
                    }
                } catch (IOException | PeFormatException | SecurityException exception) {
                    failures.add(new ScanFailure(file, failureMessage(exception)));
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exception) {
                failures.add(new ScanFailure(file, failureMessage(exception)));
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exception) {
                if (exception != null) {
                    failures.add(new ScanFailure(dir, failureMessage(exception)));
                }
                return FileVisitResult.CONTINUE;
            }
        });

        Comparator<String> order = String.CASE_INSENSITIVE_ORDER.thenComparing(
                Comparator.naturalOrder());
        files.sort(Comparator.comparing(file -> file.imports().image().headers().path().toString(), order));
        failures.sort(Comparator.comparing(failure -> failure.path().toString(), order));
        return new DirectoryAnalysis(root, files, failures, skipped[0]);
    }

    private boolean hasPeSignature(Path file) throws IOException, PeFormatException {
        try (LittleEndianReader reader = new LittleEndianReader(file)) {
            if (reader.size() < 64 || reader.u16(0, "MZ") != 0x5A4D) {
                return false;
            }
            long peOffset = reader.u32(0x3C, "e_lfanew");
            if (peOffset < 64 || peOffset > reader.size() - 4) {
                return false;
            }
            return reader.u32(peOffset, "PE Signature") == 0x00004550L;
        }
    }

    private static String failureMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank()
                ? exception.getClass().getSimpleName() : message;
    }
}

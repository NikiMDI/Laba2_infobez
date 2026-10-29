package com.nikita.stage3;

import java.util.List;
import java.util.Optional;

public final class RvaMapper {
    private static final long RVA_LIMIT = 0x1_0000_0000L;

    private final PeHeaders headers;
    private final List<PeSection> sections;

    public RvaMapper(PeHeaders headers, List<PeSection> sections) {
        this.headers = headers;
        this.sections = List.copyOf(sections);
    }

    public Mapping map(long rva, long length) throws PeFormatException {
        if (rva < 0 || rva >= RVA_LIMIT || length <= 0 || length > RVA_LIMIT - rva) {
            throw new PeFormatException(
                    "Недопустимый диапазон RVA: 0x%X, длина %d".formatted(rva, length));
        }

        long end = rva + length;
        int intersectingRegions = 0;
        boolean inHeaders = false;
        PeSection selected = null;

        if (rva < headers.sizeOfHeaders() && end > 0) {
            intersectingRegions++;
            inHeaders = true;
        }

        for (PeSection section : sections) {
            long start = section.virtualAddress();
            long span = section.mappedSize();
            if (span == 0) {
                continue;
            }
            if (start < 0 || start >= RVA_LIMIT || span < 0 || span > RVA_LIMIT - start) {
                throw new PeFormatException(
                        "Диапазон RVA секции %s выходит за 32 бита".formatted(section.name()));
            }
            if (rva < start + span && end > start) {
                intersectingRegions++;
                selected = section;
            }
        }

        if (intersectingRegions > 1) {
            throw new PeFormatException(
                    "Диапазон RVA 0x%X длиной %d пересекает несколько областей; "
                            .formatted(rva, length)
                            + "однозначное преобразование невозможно");
        }

        if (inHeaders) {
            if (length > headers.sizeOfHeaders() - rva) {
                throw new PeFormatException("Диапазон RVA выходит за область заголовков");
            }
            requireFileRange(rva, length);
            return new Mapping(rva, length, rva, Optional.empty());
        }

        if (selected == null || rva < selected.virtualAddress()) {
            throw new PeFormatException(
                    "RVA 0x%X не принадлежит заголовкам или секции".formatted(rva));
        }

        long delta = rva - selected.virtualAddress();
        if (delta >= selected.sizeOfRawData()
                || length > selected.sizeOfRawData() - delta) {
            throw new PeFormatException(
                    "RVA 0x%X: в секции %s нет %d байт на диске; "
                            .formatted(rva, selected.name(), length)
                            + "диапазон попал в виртуальный хвост или вышел за данные секции");
        }

        long fileOffset = selected.pointerToRawData() + delta;
        requireFileRange(fileOffset, length);
        return new Mapping(rva, length, fileOffset, Optional.of(selected));
    }

    private void requireFileRange(long offset, long length) throws PeFormatException {
        if (offset < 0 || offset > headers.fileSize() || length > headers.fileSize() - offset) {
            throw new PeFormatException(
                    "Преобразованный диапазон 0x%X длиной %d выходит за размер файла"
                            .formatted(offset, length));
        }
    }

    public record Mapping(
            long rva,
            long length,
            long fileOffset,
            Optional<PeSection> section) {
    }
}

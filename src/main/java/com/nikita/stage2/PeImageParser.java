package com.nikita.stage2;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

public final class PeImageParser {
    private static final int SECTION_HEADER_SIZE = 40;
    private static final int IMPORT_DIRECTORY_INDEX = 1;
    private static final int IMPORT_DESCRIPTOR_SIZE = 20;
    private static final long RVA_LIMIT = 0x1_0000_0000L;

    public PeImage parse(Path path) throws IOException, PeFormatException {
        Path normalizedPath = path.toAbsolutePath().normalize();
        try (LittleEndianReader reader = new LittleEndianReader(normalizedPath)) {
            PeHeaders headers = new PeHeaderParser().parse(normalizedPath, reader);
            List<PeSection> sections = readSections(reader, headers);
            Optional<PeDataDirectory> imports = readImportDirectory(reader, headers);

            if (imports.isPresent()) {
                PeDataDirectory directory = imports.orElseThrow();
                new RvaMapper(headers, sections).map(directory.rva(), IMPORT_DESCRIPTOR_SIZE);
            }

            return new PeImage(headers, sections, imports);
        }
    }

    private List<PeSection> readSections(LittleEndianReader reader, PeHeaders headers)
            throws IOException, PeFormatException {
        List<PeSection> sections = new ArrayList<>();

        for (int index = 0; index < headers.numberOfSections(); index++) {
            long offset = headers.sectionTableOffset() + (long) index * SECTION_HEADER_SIZE;
            byte[] nameBytes = reader.bytes(offset, 8, "Section Name");
            int nameLength = 0;
            while (nameLength < nameBytes.length && nameBytes[nameLength] != 0) {
                nameLength++;
            }

            PeSection section = new PeSection(
                    index,
                    offset,
                    new String(nameBytes, 0, nameLength, StandardCharsets.UTF_8),
                    reader.u32(offset + 8, "VirtualSize"),
                    reader.u32(offset + 12, "VirtualAddress"),
                    reader.u32(offset + 16, "SizeOfRawData"),
                    reader.u32(offset + 20, "PointerToRawData"),
                    reader.u32(offset + 36, "Section Characteristics"));

            if (section.sizeOfRawData() > 0) {
                reader.requireRange(section.pointerToRawData(), section.sizeOfRawData(),
                        "Данные секции " + section.name());
            }

            long span = section.mappedSize();
            if (span > RVA_LIMIT - section.virtualAddress()) {
                throw new PeFormatException(
                        "Диапазон RVA секции %s выходит за 32 бита".formatted(section.name()));
            }
            if (span > 0 && section.virtualAddress() < headers.sizeOfHeaders()) {
                throw new PeFormatException(
                        "RVA секции %s перекрывает заголовки".formatted(section.name()));
            }

            sections.add(section);
        }
        validateVirtualRanges(sections);
        return List.copyOf(sections);
    }

    private Optional<PeDataDirectory> readImportDirectory(
            LittleEndianReader reader, PeHeaders headers) throws IOException, PeFormatException {
        if (headers.numberOfDataDirectories() <= IMPORT_DIRECTORY_INDEX) {
            return Optional.empty();
        }

        long optionalOffset = headers.peOffset() + 4 + 20;
        long entryOffset = optionalOffset + headers.format().fixedHeaderSize()
                + IMPORT_DIRECTORY_INDEX * 8L;
        long rva = reader.u32(entryOffset, "Import Directory RVA");
        long size = reader.u32(entryOffset + 4, "Import Directory Size");

        if (rva == 0 && size == 0) {
            return Optional.empty();
        }
        if (rva == 0 || size == 0) {
            throw new PeFormatException("Import Directory: RVA и Size противоречат друг другу");
        }
        if (size < IMPORT_DESCRIPTOR_SIZE) {
            throw new PeFormatException("Import Directory короче одного дескриптора (20 байт)");
        }
        if (size > RVA_LIMIT - rva) {
            throw new PeFormatException("Диапазон Import Directory выходит за 32 бита RVA");
        }

        return Optional.of(new PeDataDirectory(entryOffset, rva, size));
    }

    private void validateVirtualRanges(List<PeSection> sections) throws PeFormatException {
        List<PeSection> sorted = new ArrayList<>(sections);
        sorted.removeIf(section -> section.mappedSize() == 0);
        sorted.sort(Comparator.comparingLong(PeSection::virtualAddress));
        for (int index = 1; index < sorted.size(); index++) {
            PeSection previous = sorted.get(index - 1);
            PeSection current = sorted.get(index);
            if (current.virtualAddress() < previous.virtualAddress() + previous.mappedSize()) {
                throw new PeFormatException(
                        "Перекрываются RVA секций %s и %s"
                                .formatted(previous.name(), current.name()));
            }
        }
    }
}

package com.nikita.stage3;

import java.io.IOException;
import java.nio.file.Path;

public final class PeHeaderParser {
    private static final long DOS_HEADER_SIZE = 64;
    private static final long E_LFANEW_OFFSET = 0x3C;
    private static final long PE_SIGNATURE = 0x00004550L;
    private static final int COFF_HEADER_SIZE = 20;
    private static final int SECTION_HEADER_SIZE = 40;

    public PeHeaders parse(Path path) throws IOException, PeFormatException {
        Path normalizedPath = path.toAbsolutePath().normalize();
        try (LittleEndianReader reader = new LittleEndianReader(normalizedPath)) {
            return parse(normalizedPath, reader);
        }
    }

    PeHeaders parse(Path normalizedPath, LittleEndianReader reader)
            throws IOException, PeFormatException {
        reader.requireRange(0, DOS_HEADER_SIZE, "MS-DOS Header");
        if (reader.u16(0, "MZ") != 0x5A4D) {
            throw new PeFormatException("Отсутствует сигнатура MZ в начале файла");
        }

        long peOffset = reader.u32(E_LFANEW_OFFSET, "e_lfanew");
        if (peOffset < DOS_HEADER_SIZE) {
            throw new PeFormatException("e_lfanew указывает внутрь MS-DOS Header");
        }
        reader.requireRange(peOffset, 4L + COFF_HEADER_SIZE, "PE Signature и COFF Header");
        if (reader.u32(peOffset, "PE Signature") != PE_SIGNATURE) {
            throw new PeFormatException(
                    "Отсутствует сигнатура PE\\0\\0 по адресу 0x%X".formatted(peOffset));
        }

        long coffOffset = peOffset + 4;
        int machine = reader.u16(coffOffset, "Machine");
        int sectionCount = reader.u16(coffOffset + 2, "NumberOfSections");
        int optionalSize = reader.u16(coffOffset + 16, "SizeOfOptionalHeader");
        int characteristics = reader.u16(coffOffset + 18, "Characteristics");
        long optionalOffset = coffOffset + COFF_HEADER_SIZE;
        reader.requireRange(optionalOffset, optionalSize, "Optional Header");
        if (optionalSize < 2) {
            throw new PeFormatException("Optional Header слишком короткий: отсутствует Magic");
        }

        int magic = reader.u16(optionalOffset, "Optional Header Magic");
        PeFormat format = switch (magic) {
            case 0x10B -> PeFormat.PE32;
            case 0x20B -> PeFormat.PE32_PLUS;
            default -> throw new PeFormatException(
                    "Неподдерживаемый Optional Header Magic: 0x%04X".formatted(magic));
        };
        int fixedSize = format.fixedHeaderSize();
        if (optionalSize < fixedSize) {
            throw new PeFormatException(
                    "Optional Header %s: нужно не менее %d байт, объявлено %d"
                            .formatted(format.displayName(), fixedSize, optionalSize));
        }

        long entryPoint = reader.u32(optionalOffset + 16, "AddressOfEntryPoint");
        long imageBase = format == PeFormat.PE32
                ? reader.u32(optionalOffset + 28, "ImageBase")
                : reader.u64Bits(optionalOffset + 24, "ImageBase");
        long sizeOfImage = reader.u32(optionalOffset + 56, "SizeOfImage");
        long sizeOfHeaders = reader.u32(optionalOffset + 60, "SizeOfHeaders");
        int subsystem = reader.u16(optionalOffset + 68, "Subsystem");
        long directoryCount = reader.u32(
                optionalOffset + fixedSize - 4, "NumberOfRvaAndSizes");
        if (directoryCount > (optionalSize - fixedSize) / 8) {
            throw new PeFormatException(
                    "NumberOfRvaAndSizes не помещается в объявленный Optional Header");
        }

        long sectionTableOffset = optionalOffset + optionalSize;
        long sectionTableSize = (long) sectionCount * SECTION_HEADER_SIZE;
        reader.requireRange(sectionTableOffset, sectionTableSize, "Таблица заголовков секций");
        if (sizeOfHeaders < sectionTableOffset + sectionTableSize
                || sizeOfHeaders > reader.size()) {
            throw new PeFormatException(
                    "SizeOfHeaders не покрывает заголовки или выходит за размер файла");
        }

        return new PeHeaders(normalizedPath, reader.size(), peOffset, machine,
                sectionCount, optionalSize, format, entryPoint, imageBase, sizeOfImage,
                sizeOfHeaders, directoryCount, sectionTableOffset, characteristics, subsystem);
    }
}

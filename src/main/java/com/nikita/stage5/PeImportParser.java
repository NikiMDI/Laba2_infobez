package com.nikita.stage5;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

public final class PeImportParser {
    private static final int DESCRIPTOR_SIZE = 20;
    private static final int MAX_LIBRARIES = 4096;
    private static final int MAX_SYMBOLS_PER_LIBRARY = 65_536;
    private static final int MAX_TOTAL_SYMBOLS = 100_000;
    private static final int MAX_NAME_BYTES = 4096;
    private static final long RVA_LIMIT = 0x1_0000_0000L;

    public PeImports parse(Path path) throws IOException, PeFormatException {
        Path normalizedPath = path.toAbsolutePath().normalize();
        try (LittleEndianReader reader = new LittleEndianReader(normalizedPath)) {
            PeImage image = new PeImageParser().parse(normalizedPath, reader);
            if (image.importDirectory().isEmpty()) {
                return new PeImports(image, List.of());
            }

            RvaMapper mapper = new RvaMapper(image.headers(), image.sections());
            PeDataDirectory directory = image.importDirectory().orElseThrow();
            List<ImportedLibrary> libraries = new ArrayList<>();
            int totalSymbols = 0;

            for (int index = 0; index <= MAX_LIBRARIES; index++) {
                if ((index + 1L) * DESCRIPTOR_SIZE > directory.size()) {
                    throw new PeFormatException(
                            "В пределах Import Directory не найден нулевой дескриптор");
                }
                long descriptorRva = directory.rva() + (long) index * DESCRIPTOR_SIZE;
                long offset = mapper.map(descriptorRva, DESCRIPTOR_SIZE).fileOffset();

                long originalFirstThunk = reader.u32(offset, "OriginalFirstThunk");
                long timestamp = reader.u32(offset + 4, "Import TimeDateStamp");
                long forwarderChain = reader.u32(offset + 8, "ForwarderChain");
                long nameRva = reader.u32(offset + 12, "DLL Name RVA");
                long firstThunk = reader.u32(offset + 16, "FirstThunk");

                if ((originalFirstThunk | timestamp | forwarderChain | nameRva | firstThunk) == 0) {
                    return new PeImports(image, libraries);
                }
                if (index == MAX_LIBRARIES) {
                    throw new PeFormatException("Превышен лимит числа импортируемых DLL");
                }
                if (nameRva == 0 || firstThunk == 0) {
                    throw new PeFormatException("В дескрипторе DLL отсутствует Name или FirstThunk");
                }
                if (originalFirstThunk == 0 && timestamp != 0) {
                    throw new PeFormatException(
                            "OriginalFirstThunk отсутствует при ненулевом TimeDateStamp: "
                                    + "имена связанного импорта надёжно восстановить нельзя");
                }

                String name = readAsciiString(reader, mapper, image.headers(), nameRva, "DLL Name");
                long lookup = originalFirstThunk == 0 ? firstThunk : originalFirstThunk;
                List<ImportedSymbol> symbols = readSymbols(reader, mapper, image.headers(),
                        lookup, firstThunk, MAX_TOTAL_SYMBOLS - totalSymbols);
                totalSymbols += symbols.size();
                libraries.add(new ImportedLibrary(name, descriptorRva, offset, nameRva,
                        originalFirstThunk, firstThunk, symbols));
            }
            throw new PeFormatException("Превышен лимит числа импортируемых DLL");
        }
    }

    private List<ImportedSymbol> readSymbols(
            LittleEndianReader reader, RvaMapper mapper, PeHeaders headers,
            long lookup, long firstThunk, int remainingBudget) throws IOException, PeFormatException {
        boolean plus = headers.format() == PeFormat.PE32_PLUS;
        int width = plus ? 8 : 4;
        long ordinalMask = plus ? Long.MIN_VALUE : 0x8000_0000L;
        int allowed = Math.min(MAX_SYMBOLS_PER_LIBRARY, remainingBudget);
        List<ImportedSymbol> symbols = new ArrayList<>();

        for (int index = 0; index <= allowed; index++) {
            long lookupRva = indexedRva(lookup, index, width, "Lookup Table");
            long offset = mapper.map(lookupRva, width).fileOffset();
            long value = plus ? reader.u64Bits(offset, "Import Thunk")
                    : reader.u32(offset, "Import Thunk");
            if (value == 0) {
                return List.copyOf(symbols);
            }
            if (index == allowed) {
                throw new PeFormatException("Превышен лимит числа импортируемых символов");
            }
            long iatRva = indexedRva(firstThunk, index, width, "IAT");

            if ((value & ordinalMask) != 0) {
                if ((value & ~(ordinalMask | 0xFFFFL)) != 0) {
                    throw new PeFormatException("В ordinal-записи установлены зарезервированные биты");
                }
                symbols.add(new ImportedSymbol(Optional.empty(),
                        OptionalInt.of((int) (value & 0xFFFFL)), OptionalInt.empty(), lookupRva, iatRva));
            } else {
                if (value > 0x7FFF_FFFFL) {
                    throw new PeFormatException("Hint/Name RVA содержит зарезервированные биты");
                }
                long nameOffset = mapper.map(value, 2).fileOffset();
                int hint = reader.u16(nameOffset, "Import Hint");
                String name = readAsciiString(reader, mapper, headers, value + 2, "Import Name");
                symbols.add(new ImportedSymbol(Optional.of(name), OptionalInt.empty(),
                        OptionalInt.of(hint), lookupRva, iatRva));
            }
        }
        throw new PeFormatException("Не найден конец таблицы импортируемых символов");
    }

    private String readAsciiString(
            LittleEndianReader reader, RvaMapper mapper, PeHeaders headers,
            long rva, String field) throws IOException, PeFormatException {
        RvaMapper.Mapping mapping = mapper.map(rva, 1);
        long remaining = mapping.section().isPresent()
                ? mapping.section().orElseThrow().sizeOfRawData()
                    - (rva - mapping.section().orElseThrow().virtualAddress())
                : headers.sizeOfHeaders() - rva;
        int length = (int) Math.min(remaining, MAX_NAME_BYTES);
        byte[] bytes = reader.bytes(mapping.fileOffset(), length, field);

        for (int index = 0; index < bytes.length; index++) {
            if (bytes[index] == 0) {
                if (index == 0) {
                    throw new PeFormatException(field + ": пустое имя");
                }
                return new String(bytes, 0, index, StandardCharsets.US_ASCII);
            }
            if ((bytes[index] & 0xFF) > 0x7F) {
                throw new PeFormatException(field + ": имя содержит байты вне ASCII");
            }
        }
        throw new PeFormatException(
                field + ": нет нулевого завершения в доступной области или превышен лимит 4096 байт");
    }

    private long indexedRva(long base, int index, int width, String field) throws PeFormatException {
        long delta = (long) index * width;
        if (base < 0 || base >= RVA_LIMIT || delta > RVA_LIMIT - base - width) {
            throw new PeFormatException(field + ": адрес элемента выходит за 32 бита RVA");
        }
        return base + delta;
    }
}

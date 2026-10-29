package com.nikita.stage5;

import java.io.PrintStream;
import java.util.Objects;

public final class DetailedReportPrinter {
    public void print(DirectoryAnalysis analysis, PrintStream out) throws PeFormatException {
        Objects.requireNonNull(analysis, "analysis");
        Objects.requireNonNull(out, "out");
        for (int stage = 1; stage <= 4; stage++) {
            printStage(analysis, stage, out);
        }
    }

    private void printStage(DirectoryAnalysis analysis, int stage, PrintStream out)
            throws PeFormatException {
        String title = switch (stage) {
            case 1 -> "Этап 1. Заголовки PE";
            case 2 -> "Этап 2. Секции и положение таблицы импорта";
            case 3 -> "Этап 3. DLL и импортируемые символы";
            case 4 -> "Этап 4. Сопоставление с сетевыми функциями";
            default -> throw new IllegalArgumentException("Неизвестный этап: " + stage);
        };
        out.println();
        out.println("============================================================");
        out.println(title);
        if (stage == 3) {
            out.println("Адреса: Lookup RVA — RVA записи таблицы поиска; IAT RVA — RVA соответствующей ячейки IAT.");
        }
        if (stage == 4) {
            out.printf("Различных имён в списке задания: %d.%n", NetworkFunctionCatalog.size());
            out.println("Сопоставление: полное имя с учётом регистра, без добавления суффиксов A/W.");
        }
        if (analysis.files().isEmpty()) {
            out.println("Нет успешно проанализированных PE-файлов для этого этапа.");
        }
        for (NetworkAnalysis file : analysis.files()) {
            out.println();
            out.println("Файл: " + analysis.directory().relativize(file.imports().image().headers().path()));
            switch (stage) {
                case 1 -> printHeaders(file.imports().image().headers(), out);
                case 2 -> printImage(file.imports().image(), out);
                case 3 -> printImports(file.imports(), out);
                case 4 -> printMatches(file, out);
                default -> throw new IllegalArgumentException("Неизвестный этап: " + stage);
            }
        }
    }

    private void printHeaders(PeHeaders headers, PrintStream out) {
        out.println("Полный путь: " + headers.path());
        out.printf("Размер файла: %d байт (0x%X)%n", headers.fileSize(), headers.fileSize());
        out.println("Сигнатуры распознаны: MZ, PE\\0\\0");
        out.printf("Смещение PE (e_lfanew из поля по адресу 0x3C): 0x%08X%n", headers.peOffset());
        long coffOffset = headers.peOffset() + 4;
        long optionalOffset = coffOffset + 20;
        out.printf("Начало COFF Header: 0x%X + 4 = 0x%X%n", headers.peOffset(), coffOffset);
        out.printf("Начало Optional Header: 0x%X + 20 = 0x%X%n", coffOffset, optionalOffset);
        out.printf("Формат: %s (Magic 0x%04X)%n",
                headers.format().displayName(), headers.format().magic());
        out.printf("Архитектура: %s (Machine 0x%04X)%n", headers.machineName(), headers.machine());
        out.printf("Characteristics: 0x%04X; Subsystem: 0x%04X%n",
                headers.characteristics(), headers.subsystem());
        out.println("Признак DLL: " + (headers.isDll() ? "да" : "нет"));
        out.printf("Количество секций: %d%n", headers.numberOfSections());
        out.printf("Размер Optional Header: %d байт (0x%X)%n",
                headers.optionalHeaderSize(), headers.optionalHeaderSize());
        out.printf("Точка входа (RVA): 0x%08X%n", headers.entryPointRva());
        String imageBaseFormat = headers.format() == PeFormat.PE32 ? "0x%08X" : "0x%016X";
        out.printf("Базовый адрес образа: " + imageBaseFormat + "%n", headers.imageBase());
        out.printf("Размер образа в памяти: %d байт (0x%X)%n", headers.sizeOfImage(), headers.sizeOfImage());
        out.printf("Размер заголовков: %d байт (0x%X)%n", headers.sizeOfHeaders(), headers.sizeOfHeaders());
        out.printf("Количество Data Directories: %d%n", headers.numberOfDataDirectories());
        out.printf("Начало таблицы секций: 0x%X + 0x%X = 0x%X%n",
                optionalOffset, headers.optionalHeaderSize(), headers.sectionTableOffset());
        out.printf("Таблица секций (смещение в файле): 0x%08X%n", headers.sectionTableOffset());
    }

    private void printImage(PeImage image, PrintStream out) throws PeFormatException {
        out.println();
        out.println("Адреса и размеры в таблице секций — шестнадцатеричные.");
        out.printf("%-3s %-9s %-12s %-12s %-12s %-12s %-12s %-12s%n",
                "№", "Имя", "HeaderOffset", "RVA", "VirtualSize", "Raw Offset", "Raw Size", "Flags");
        for (PeSection section : image.sections()) {
            out.printf("%-3d %-9s 0x%08X   0x%08X   0x%08X   0x%08X   0x%08X   0x%08X%n",
                    section.index() + 1, section.name(), section.headerOffset(),
                    section.virtualAddress(), section.virtualSize(), section.pointerToRawData(),
                    section.sizeOfRawData(), section.characteristics());
        }

        out.println();
        if (image.importDirectory().isEmpty()) {
            out.println("Import Directory отсутствует в заголовке.");
            return;
        }

        PeHeaders headers = image.headers();
        PeDataDirectory directory = image.importDirectory().orElseThrow();
        long optionalOffset = headers.peOffset() + 4 + 20;
        long directoriesOffset = optionalOffset + headers.format().fixedHeaderSize();
        out.printf("Начало Data Directories: 0x%X + 0x%X = 0x%X%n",
                optionalOffset, headers.format().fixedHeaderSize(), directoriesOffset);
        out.printf("Запись Import Directory: 0x%X + 1 * 8 = 0x%X%n",
                directoriesOffset, directory.entryOffset());
        out.printf("Запись Import Directory в файле: 0x%08X%n", directory.entryOffset());
        out.printf("Import Directory RVA: 0x%08X%n", directory.rva());
        out.printf("Import Directory Size: 0x%X (%d байт)%n", directory.size(), directory.size());

        RvaMapper.Mapping mapping = new RvaMapper(headers, image.sections()).map(directory.rva(), 20);
        if (mapping.section().isPresent()) {
            PeSection section = mapping.section().orElseThrow();
            long delta = directory.rva() - section.virtualAddress();
            out.println("Секция импорта: " + section.name());
            out.printf("Смещение внутри секции: 0x%X - 0x%X = 0x%X%n",
                    directory.rva(), section.virtualAddress(), delta);
            out.printf("Расчёт файлового смещения: 0x%X + 0x%X = 0x%X%n",
                    section.pointerToRawData(), delta, mapping.fileOffset());
        } else {
            out.println("Import Directory находится в области заголовков; File Offset = RVA.");
        }
        out.printf("Import Directory File Offset: 0x%08X%n", mapping.fileOffset());
    }

    private void printImports(PeImports imports, PrintStream out) throws PeFormatException {
        out.println();
        out.printf("Обычный импорт: DLL — %d, символов — %d%n",
                imports.libraries().size(), imports.symbolCount());
        if (imports.image().importDirectory().isEmpty()) {
            out.println("Обычная таблица импорта отсутствует.");
        } else if (imports.libraries().isEmpty()) {
            out.println("В таблице импорта нет дескрипторов DLL.");
        }

        RvaMapper mapper = new RvaMapper(imports.image().headers(), imports.image().sections());
        for (ImportedLibrary library : imports.libraries()) {
            out.println();
            out.printf("%s — %d символов%n", library.name(), library.symbols().size());
            out.printf("  Дескриптор: RVA 0x%08X, File Offset 0x%08X%n",
                    library.descriptorRva(), library.descriptorOffset());
            out.printf("  Имя DLL: RVA 0x%08X, File Offset 0x%08X%n",
                    library.nameRva(), mapper.map(library.nameRva(), 1).fileOffset());
            out.printf("  OriginalFirstThunk: 0x%08X; FirstThunk: 0x%08X%n",
                    library.originalFirstThunk(), library.firstThunk());
            out.println(library.originalFirstThunk() == 0
                    ? "  Таблица поиска: FirstThunk, поскольку OriginalFirstThunk = 0."
                    : "  Таблица поиска: OriginalFirstThunk.");
            for (ImportedSymbol symbol : library.symbols()) {
                String kind = symbol.isByOrdinal()
                        ? "ordinal " + symbol.ordinal().orElseThrow()
                        : "Hint " + symbol.hint().orElseThrow();
                out.printf("  %s [%s; Lookup RVA 0x%08X; IAT RVA 0x%08X]%n",
                        symbol.displayName(), kind, symbol.lookupRva(), symbol.iatRva());
            }
        }
        out.println();
        out.printf("Итого: %d DLL, %d импортируемых символов.%n",
                imports.libraries().size(), imports.symbolCount());
    }

    private void printMatches(NetworkAnalysis analysis, PrintStream out) {
        out.println();
        out.printf("Импортов по имени: %d; по ordinal без имени: %d.%n",
                analysis.namedImportCount(), analysis.ordinalImportCount());
        if (!analysis.hasMatches()) {
            out.println("Совпадений с заданным списком не найдено.");
        } else {
            out.printf("Найдено совпадений (записей импорта): %d%n", analysis.matches().size());
            for (NetworkMatch match : analysis.matches()) {
                out.printf("  %s -> %s%n", match.libraryName(), match.functionName());
                out.printf("    Lookup RVA: 0x%08X; IAT RVA: 0x%08X%n",
                        match.lookupRva(), match.iatRva());
            }
        }
    }
}

package com.nikita.stage2;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        // UTF-8 сохраняет русский текст и при перенаправлении вывода в файл.
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(System.err, true, StandardCharsets.UTF_8);
        int exitCode = run(args, out, err);
        System.exit(exitCode);
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 1
                && ("--help".equals(args[0]) || "-h".equals(args[0]))) {
            printHelp(out);
            return 0;
        }
        if (args.length != 1) {
            err.println("Укажите путь к одному PE-файлу.");
            printHelp(err);
            return 2;
        }
        String input = args[0];
        try {
            Path path = Path.of(input);
            if (Files.isDirectory(path)) {
                err.println("На этапе 2 укажите файл. Обход каталога будет на этапе 5.");
                return 2;
            }
            PeImage image = new PeImageParser().parse(path);
            out.println("Этап 2. Секции и расположение Import Directory");
            printHeaders(image.headers(), out);
            printImage(image, out);
            return 0;
        } catch (InvalidPathException exception) {
            err.println("Некорректный путь: " + exception.getInput());
            return 2;
        } catch (NoSuchFileException exception) {
            err.println("Файл не найден: " + input);
        } catch (AccessDeniedException exception) {
            err.println("Нет доступа к файлу: " + input);
        } catch (PeFormatException exception) {
            err.println("Ошибка структуры PE: " + exception.getMessage());
        } catch (IOException | SecurityException exception) {
            err.println("Ошибка чтения файла: " + exception.getMessage());
        }
        return 1;
    }

    private static void printHelp(PrintStream out) {
        out.println("PE Network Analyzer — этап 2: секции и расположение импорта");
        out.println("Запуск: com.nikita.stage2.Main \"путь к файлу\"");
        out.println("Справка: com.nikita.stage2.Main --help");
        out.println("В IDE: com.nikita.stage2.Stage2Demo.main");
    }

    private static void printHeaders(PeHeaders headers, PrintStream out) {
        out.println("Заголовки PE распознаны");
        out.println("Файл: " + headers.path());
        out.printf("Размер файла: %d байт%n", headers.fileSize());
        out.println("Сигнатуры: MZ, PE\\0\\0");
        out.printf("Смещение PE (e_lfanew): 0x%08X%n", headers.peOffset());
        out.printf("Формат: %s (Magic 0x%04X)%n",
                headers.format().displayName(), headers.format().magic());
        out.printf("Архитектура: %s (Machine 0x%04X)%n",
                headers.machineName(), headers.machine());
        out.println("Признак DLL: " + (headers.isDll() ? "да" : "нет"));
        out.printf("Количество секций: %d%n", headers.numberOfSections());
        out.printf("Размер Optional Header: %d байт%n", headers.optionalHeaderSize());
        out.printf("Точка входа (RVA): 0x%08X%n", headers.entryPointRva());
        String imageBaseFormat = headers.format() == PeFormat.PE32 ? "0x%08X" : "0x%016X";
        out.printf("Базовый адрес образа: " + imageBaseFormat + "%n", headers.imageBase());
        out.printf("Размер образа в памяти: %d байт%n", headers.sizeOfImage());
        out.printf("Размер заголовков: %d байт%n", headers.sizeOfHeaders());
        out.printf("Количество Data Directories: %d%n", headers.numberOfDataDirectories());
        out.printf("Таблица секций (смещение в файле): 0x%08X%n", headers.sectionTableOffset());
    }

    private static void printImage(PeImage image, PrintStream out) throws PeFormatException {
        out.println();
        out.println("Таблица секций. Адреса и размеры ниже — шестнадцатеричные.");
        out.printf("%-3s %-9s %-12s %-12s %-12s %-12s %-12s%n",
                "№", "Имя", "Описание", "RVA", "VirtualSize", "Raw Offset", "Raw Size");
        for (PeSection section : image.sections()) {
            out.printf("%-3d %-9s 0x%08X   0x%08X   0x%08X   0x%08X   0x%08X%n",
                    section.index() + 1, section.name(), section.headerOffset(),
                    section.virtualAddress(), section.virtualSize(),
                    section.pointerToRawData(), section.sizeOfRawData());
        }

        out.println();
        if (image.importDirectory().isEmpty()) {
            out.println("Import Directory отсутствует в заголовке.");
            out.println("Имена DLL и функций на этапе 2 не читаются.");
            return;
        }

        PeDataDirectory directory = image.importDirectory().orElseThrow();
        RvaMapper.Mapping mapping = new RvaMapper(image.headers(), image.sections())
                .map(directory.rva(), 20);
        out.printf("Запись Import Directory в файле: 0x%08X%n", directory.entryOffset());
        out.printf("Import Directory RVA: 0x%08X%n", directory.rva());
        out.printf("Import Directory Size: 0x%X (%d байт)%n", directory.size(), directory.size());

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
        out.println("Проверена доступность первых 20 байт Import Directory.");
        out.println("Имена DLL и функций будут читаться на этапе 3.");
    }
}

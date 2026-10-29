package com.nikita.stage1;

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
        if (args.length == 1 && ("--help".equals(args[0]) || "-h".equals(args[0]))) {
            printHelp(out);
            return 0;
        }
        if (args.length != 1) {
            err.println("Укажите путь к одному PE-файлу.");
            printHelp(err);
            return 2;
        }
        try {
            Path path = Path.of(args[0]);
            if (Files.isDirectory(path)) {
                err.println("На этапе 1 укажите файл. Обход каталога будет на этапе 5.");
                return 2;
            }
            PeHeaderParser parser = new PeHeaderParser();
            PeHeaders headers = parser.parse(path);
            printHeaders(headers, out);
            return 0;
        } catch (InvalidPathException exception) {
            err.println("Некорректный путь: " + exception.getInput());
            return 2;
        } catch (NoSuchFileException exception) {
            err.println("Файл не найден: " + args[0]);
        } catch (AccessDeniedException exception) {
            err.println("Нет доступа к файлу: " + args[0]);
        } catch (PeFormatException exception) {
            err.println("Ошибка структуры PE: " + exception.getMessage());
        } catch (IOException | SecurityException exception) {
            err.println("Ошибка чтения файла: " + exception.getMessage());
        }
        return 1;
    }

    private static void printHelp(PrintStream out) {
        out.println("PE Network Analyzer — этап 1: чтение заголовков");
        out.println("Запуск: com.nikita.stage1.Main \"путь к файлу\"");
        out.println("Справка: com.nikita.stage1.Main --help");
        out.println("В IDE: com.nikita.stage1.Stage1Demo.main");
    }

    private static void printHeaders(PeHeaders headers, PrintStream out) {
        out.println("Этап 1. Заголовки PE распознаны");
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
        out.println("Импорт и сетевые функции на этом этапе ещё не анализируются.");
    }
}

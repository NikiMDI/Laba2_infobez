package com.nikita.stage5;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(System.err, true, StandardCharsets.UTF_8);
        System.exit(run(args, out, err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 1 && ("--help".equals(args[0]) || "-h".equals(args[0]))) {
            printHelp(out);
            return 0;
        }
        boolean explicitMode = args.length == 2
                && ("--details".equals(args[0]) || "--brief".equals(args[0]));
        if ((!explicitMode && args.length != 1)
                || (args.length == 1
                    && ("--details".equals(args[0]) || "--brief".equals(args[0])))) {
            err.println("Укажите путь к каталогу с PE-файлами.");
            printHelp(err);
            return 2;
        }

        boolean details = !explicitMode || "--details".equals(args[0]);
        String input = args[explicitMode ? 1 : 0];
        try {
            DirectoryAnalysis analysis = new DirectoryScanner().scan(Path.of(input));
            printReport(analysis, out, err, details);
            return analysis.hasFailures() ? 1 : 0;
        } catch (InvalidPathException exception) {
            err.println("Некорректный путь: " + exception.getInput());
            return 2;
        } catch (NotDirectoryException exception) {
            err.println("Укажите каталог: " + input);
            return 2;
        } catch (NoSuchFileException exception) {
            err.println("Каталог не найден: " + input);
        } catch (AccessDeniedException exception) {
            err.println("Нет доступа к каталогу: " + input);
        } catch (PeFormatException exception) {
            err.println("Ошибка построения полного отчёта: " + exception.getMessage());
        } catch (IOException | SecurityException exception) {
            err.println("Ошибка обхода каталога: " + exception.getMessage());
        }
        return 1;
    }

    private static void printHelp(PrintStream out) {
        out.println("PE Network Analyzer — этап 5: поиск сетевых функций в каталоге");
        out.println("Запуск (полный отчёт по этапам 1–5): com.nikita.stage5.Main \"путь к каталогу\"");
        out.println("Полный отчёт: com.nikita.stage5.Main --details \"путь к каталогу\"");
        out.println("Краткий отчёт: com.nikita.stage5.Main --brief \"путь к каталогу\"");
        out.println("Проверяются PE-файлы в каталоге и вложенных папках, включая DLL и EXE.");
        out.println("Полный отчёт в IDE: com.nikita.stage5.Stage5Demo.main");
        out.println("Все этапы в IDE: com.nikita.stage5.FullReportDemo.main");
    }

    private static void printReport(
            DirectoryAnalysis analysis, PrintStream out, PrintStream err, boolean details)
            throws PeFormatException {
        out.println(details ? "Полный анализ PE-файлов: этапы 1–5"
                : "Этап 5. Поиск сетевых функций в каталоге");
        out.println("Каталог: " + analysis.directory());
        out.println("Обход: каталог и вложенные папки. Формат PE определяется по содержимому.");

        DetailedReportPrinter printer = new DetailedReportPrinter();
        if (details) {
            printer.print(analysis, out);
        } else {
            printBriefFiles(analysis, out);
        }

        for (ScanFailure failure : analysis.failures()) {
            err.printf("Ошибка: %s — %s%n", failure.path(), failure.message());
        }

        out.println();
        if (details) {
            out.println("============================================================");
            out.println("Этап 5. Итог по каталогу");
            out.println("Совпадения: исследуемый файл -> DLL -> функция");
            if (analysis.matchedFileCount() == 0) {
                out.println("  Совпадений с заданным списком не найдено.");
            }
            for (NetworkAnalysis file : analysis.files()) {
                Path path = file.imports().image().headers().path();
                for (NetworkMatch match : file.matches()) {
                    out.printf("  %s -> %s -> %s%n", analysis.directory().relativize(path),
                            match.libraryName(), match.functionName());
                }
            }
            out.println();
        }
        out.printf("Итого: успешно проверено PE-файлов — %d; с совпадениями — %d; совпадений — %d.%n",
                analysis.files().size(), analysis.matchedFileCount(), analysis.matchCount());
        out.printf("Пропущено файлов без PE-сигнатуры: %d; ошибок: %d.%n",
                analysis.skippedFileCount(), analysis.failures().size());
        out.println("Результат относится к обычному импорту по именам из списка задания.");
    }

    private static void printBriefFiles(DirectoryAnalysis analysis, PrintStream out) {
        for (NetworkAnalysis file : analysis.files()) {
            out.println();
            Path path = file.imports().image().headers().path();
            out.println("Файл: " + analysis.directory().relativize(path));
            if (!file.hasMatches()) {
                out.println("  Совпадений с заданным списком не найдено.");
                continue;
            }
            for (NetworkMatch match : file.matches()) {
                out.printf("  %s -> %s%n", match.libraryName(), match.functionName());
            }
        }

    }
}

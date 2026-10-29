package com.nikita.stage1;

/**
 * Учебная точка входа для IntelliJ IDEA.
 * Откройте этот класс и нажмите Run рядом с main.
 */
public final class Stage1Demo {
    // Для своего примера измените эту строку. В Java каждый \ записывается как \\.
    private static final String FILE_TO_ANALYZE = "C:\\Users\\Nikita\\Desktop\\Магистры\\Магистры\\PE Bear\\PE-bear.exe";

    private Stage1Demo() {
    }

    public static void main(String[] args) {
        String[] arguments = args;
        if (arguments.length == 0) {
            // Без Program arguments используем готовый пример.
            arguments = new String[] {FILE_TO_ANALYZE};
        }

        // Запускаем тот же анализ, что и обычная консольная программа.
        Main.main(arguments);
    }
}

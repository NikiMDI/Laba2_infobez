package com.nikita.stage3;

import java.nio.file.Path;

public record PeHeaders(
        // Полный путь к исследованному файлу.
        Path path,
        // Размер файла на диске в байтах.
        long fileSize,
        // Смещение PE Signature от начала файла.
        // Получается из поля e_lfanew.
        long peOffset,
        // Числовой код архитектуры процессора.
        int machine,
        // Количество заголовков секций.
        int numberOfSections,
        // Полный размер Optional Header.
        int optionalHeaderSize,
        // Определённый вариант: PE32 или PE32+.
        PeFormat format,
        //RVA точки входа - адрес относительно начала образа в памяти,
        long entryPointRva,
        //Предпочтительный базовый адрес образа.
        long imageBase,
        // Размер образа в памяти.
        long sizeOfImage,
        // Общий размер заголовков с учётом выравнивания.
        long sizeOfHeaders,
        // Объявленное число записей Data Directories.
        long numberOfDataDirectories,
        // Вычисленное начало таблицы секций в файле.
        long sectionTableOffset,
        // Битовые признаки из COFF Header.
        int characteristics,
        // Код подсистемы из Optional Header.
        int subsystem
) {

    public String machineName() {
        return switch (machine) {
            case 0x014C -> "x86";
            case 0x8664 -> "x64 (AMD64)";
            case 0x01C0 -> "ARM";
            case 0x01C4 -> "ARM Thumb-2";
            case 0xAA64 -> "ARM64";
            case 0x0200 -> "IA-64";
            default -> "неизвестная архитектура";
        };
    }

    public boolean isDll() {
        return (characteristics & 0x2000) != 0;
    }
}

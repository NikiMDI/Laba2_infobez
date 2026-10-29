package com.nikita.stage1;

/** Ожидаемая ошибка структуры анализируемого файла. */
public final class PeFormatException extends Exception {
    private static final long serialVersionUID = 1L;

    public PeFormatException(String message) {
        super(message);
    }
}

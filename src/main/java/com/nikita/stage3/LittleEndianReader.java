package com.nikita.stage3;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

final class LittleEndianReader implements AutoCloseable {
    private final FileChannel channel;
    private final long size;

    LittleEndianReader(Path path) throws IOException {
        channel = FileChannel.open(path, StandardOpenOption.READ);
        long detectedSize;
        try {
            detectedSize = channel.size();
        } catch (IOException exception) {
            channel.close();
            throw exception;
        }
        size = detectedSize;
    }

    long size() {
        return size;
    }

    byte[] bytes(long offset, int length, String field) throws IOException, PeFormatException {
        return read(offset, length, field).array();
    }

    void requireRange(long offset, long length, String field) throws PeFormatException {
        if (offset < 0 || length < 0 || offset > size || length > size - offset) {
            throw new PeFormatException(
                    "%s: диапазон 0x%X длиной %d байт выходит за размер файла (%d байт)"
                            .formatted(field, offset, length, size));
        }
    }

    int u16(long offset, String field) throws IOException, PeFormatException {
        return Short.toUnsignedInt(read(offset, 2, field).getShort());
    }

    long u32(long offset, String field) throws IOException, PeFormatException {
        return Integer.toUnsignedLong(read(offset, 4, field).getInt());
    }

    long u64Bits(long offset, String field) throws IOException, PeFormatException {
        return read(offset, 8, field).getLong();
    }

    private ByteBuffer read(long offset, int length, String field)
            throws IOException, PeFormatException {
        requireRange(offset, length, field);
        ByteBuffer buffer = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN);
        while (buffer.hasRemaining()) {
            int count = channel.read(buffer, offset + buffer.position());
            if (count < 0) {
                throw new IOException("Файл изменился во время чтения поля " + field);
            }
            if (count == 0) {
                throw new IOException("Не удалось прочитать поле " + field);
            }
        }
        buffer.flip();
        return buffer;
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}

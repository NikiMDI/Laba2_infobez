package com.nikita.stage5;

public record PeSection(
        int index,
        long headerOffset,
        String name,
        long virtualSize,
        long virtualAddress,
        long sizeOfRawData,
        long pointerToRawData,
        long characteristics) {

    public long mappedSize() {
        return Math.max(virtualSize, sizeOfRawData);
    }
}

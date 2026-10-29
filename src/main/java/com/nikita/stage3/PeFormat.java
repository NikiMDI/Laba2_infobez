package com.nikita.stage3;

public enum PeFormat {
    PE32(0x10B, 96),
    PE32_PLUS(0x20B, 112);

    private final int magic;
    private final int fixedHeaderSize;

    PeFormat(int magic, int fixedHeaderSize) {
        this.magic = magic;
        this.fixedHeaderSize = fixedHeaderSize;
    }

    public int magic() {
        return magic;
    }

    public int fixedHeaderSize() {
        return fixedHeaderSize;
    }

    public String displayName() {
        return this == PE32 ? "PE32" : "PE32+";
    }
}

package com.nikita.stage5;

import java.util.Objects;

public record NetworkMatch(
        String libraryName,
        String functionName,
        long lookupRva,
        long iatRva) {

    public NetworkMatch {
        Objects.requireNonNull(libraryName, "libraryName");
        Objects.requireNonNull(functionName, "functionName");
    }
}

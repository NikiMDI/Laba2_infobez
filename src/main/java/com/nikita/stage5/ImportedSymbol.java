package com.nikita.stage5;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

public record ImportedSymbol(
        Optional<String> name,
        OptionalInt ordinal,
        OptionalInt hint,
        long lookupRva,
        long iatRva) {

    public ImportedSymbol {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(ordinal, "ordinal");
        Objects.requireNonNull(hint, "hint");
        if (name.isPresent() == ordinal.isPresent()
                || name.isPresent() != hint.isPresent()) {
            throw new IllegalArgumentException("Импорт должен иметь имя с Hint либо ordinal");
        }
    }

    public boolean isByOrdinal() {
        return ordinal.isPresent();
    }

    public String displayName() {
        return name.orElseGet(() -> "#" + ordinal.orElseThrow());
    }
}

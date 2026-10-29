package com.nikita.stage5;

public final class Stage5Demo {
    private static final String DIRECTORY_TO_ANALYZE =
            "C:\\Users\\Nikita\\Desktop\\Магистры\\Магистры\\PE Bear";

    private Stage5Demo() {
    }

    public static void main(String[] args) {
        String[] directoryArguments = args.length == 0
                ? new String[] {DIRECTORY_TO_ANALYZE} : args;
        Main.main(directoryArguments);
    }
}

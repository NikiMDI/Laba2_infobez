package com.nikita.stage2;

public final class Stage2Demo {
    private static final String FILE_TO_ANALYZE =
            "C:\\Users\\Nikita\\Desktop\\Магистры\\Магистры\\PE Bear\\PE-bear.exe";

    private Stage2Demo() {
    }

    public static void main(String[] args) {
        String[] fileArguments = args.length == 0 ? new String[] {FILE_TO_ANALYZE} : args;
        Main.main(fileArguments);
    }
}

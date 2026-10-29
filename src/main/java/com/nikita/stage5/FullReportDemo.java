package com.nikita.stage5;

public final class FullReportDemo {
    private static final String DIRECTORY_TO_ANALYZE =
            "C:\\Users\\Nikita\\Desktop\\Магистры\\Магистры\\PE Bear";

    private FullReportDemo() {
    }

    public static void main(String[] args) {
        String[] directoryArguments = args.length == 0
                ? new String[] {DIRECTORY_TO_ANALYZE} : args;
        if (directoryArguments.length == 1
                && ("--help".equals(directoryArguments[0]) || "-h".equals(directoryArguments[0]))) {
            Main.main(directoryArguments);
            return;
        }
        String[] fullArguments = new String[directoryArguments.length + 1];
        fullArguments[0] = "--details";
        System.arraycopy(directoryArguments, 0, fullArguments, 1, directoryArguments.length);
        Main.main(fullArguments);
    }
}

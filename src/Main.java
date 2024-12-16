import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

public class Main {

    private interface Encryptor {
        long encrypt(long data);

        long decrypt(long data);
    }


    private static class DesEncryptor implements Encryptor {

        private static final long ITERATIONS_COUNT = 16L;
        private static final long S_WIDTH = 16L;
        private static final long BITS = 64L;
        private static final long BITS_HALF = 32L;
        private static final long MASK_1 = 0x0000000000000001L;
        private static final long MASK_4 = 0x000000000000000FL;
        private static final long MASK_6 = 0x000000000000003FL;
        private static final long MASK_28 = 0x000000000FFFFFFFL;
        private static final long MASK_32 = 0x00000000FFFFFFFFL;
        private static final long MASK_48 = 0x0000FFFFFFFFFFFFL;
        private static final long MASK_56 = 0x00FFFFFFFFFFFFFFL;

        private static final long[] IP = new long[]{
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
        };

        private static final long[] IP_minus1 = new long[]{
                40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25,
        };

        private static final long[] E = new long[]{
                32, 1, 2, 3, 4, 5,
                4, 5, 6, 7, 8, 9,
                8, 9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32, 1
        };

        private static final long[] P = new long[]{
                16, 7, 20, 21,
                29, 12, 28, 17,
                1, 15, 23, 26,
                5, 18, 31, 10,
                2, 8, 24, 14,
                32, 27, 3, 9,
                19, 13, 30, 6,
                22, 11, 4, 25
        };

        private static final long[] G = new long[]{
                57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
        };

        private static final long[] H = new long[]{
                14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
        };

        private static final long[][] S = new long[][]{
                new long[]{
                        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
                },
                new long[]{
                        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
                },
                new long[]{
                        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
                },
                new long[]{
                        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
                },
                new long[]{
                        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3

                },
                new long[]{
                        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
                },
                new long[]{
                        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12

                },
                new long[]{
                        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
                }
        };
        private static final long[] delta = new long[]{
                1,
                1,
                2,
                2,
                2,
                2,
                2,
                2,
                1,
                2,
                2,
                2,
                2,
                2,
                2,
                1
        };

        protected final long key;

        public DesEncryptor(long key) {
            this.key = key;
        }

        private static long permuted(long value, long[] permutation) {
            long result = 0L;
            for (int i = 0; i < permutation.length; i++) {
                if (permutation[i] < 1L || permutation[i] > BITS)
                    throw new IllegalArgumentException("permutation item must be between 1 and 64");
                result |= (((value >> (permutation[i] - 1L)) & MASK_1) << i);
            }
            return result;
        }

        private static long K(long key, long i) {
            key = permuted(key, G);

            long c = (key >> 28L) & MASK_28;
            long d = key & MASK_28;

            long steps = Arrays.stream(delta).limit(i + 1).sum();
            c = (((c << steps) & MASK_28) | ((c >> (28L - steps)))) & MASK_28;
            d = (((d << steps) & MASK_28) | ((d >> (28L - steps)))) & MASK_28;

            key = ((c << 28L) | d) & MASK_56;

            key = permuted(key, H);

            return key;
        }

        private static long encryptionFunction(long r, long k) {
            r = permuted(r & MASK_32, E) & MASK_48;
            k &= MASK_48;
            long result = 0L;
            long blocksCount = S.length;
            long b = r ^ k;

            for (int i = 0; i < S.length; ++i) {
                long bi = (b >> (6L * (blocksCount - 1L - i))) & MASK_6;
                long row = (((bi >> 5L) & MASK_1) << 1L) | (bi & MASK_1);
                long column = (bi >> 1L) & MASK_4;
                bi = S[i][(int) (S_WIDTH * row + column)] & MASK_4;
                result |= (bi << (4L * (blocksCount - 1L - i)));
            }

            result = permuted(result, P);
            return result;
        }

        @Override
        public long encrypt(long data) {
            data = permuted(data, IP);

            long L0, R0, L1 = (data >> BITS_HALF) & MASK_32, R1 = data & MASK_32;

            for (int i = 0; i < ITERATIONS_COUNT; i++) {
                L0 = L1;
                R0 = R1;
                L1 = R0;
                R1 = L0 ^ encryptionFunction(R0, K(key, i));
            }

            data = ((R1 & MASK_32) << BITS_HALF) | (L1 & MASK_32);
            data = permuted(data, IP_minus1);

            return data;
        }

        @Override
        public long decrypt(long data) {
            data = permuted(data, IP);

            long L0, R0, R1 = (data >> BITS_HALF) & MASK_32, L1 = data & MASK_32;

            for (int i = (int) (ITERATIONS_COUNT - 1L); i >= 0; --i) {
                L0 = L1;
                R0 = R1;
                R1 = L0;
                L1 = R0 ^ encryptionFunction(L0, K(key, i));
            }

            data = ((L1 & MASK_32) << BITS_HALF) | (R1 & MASK_32);
            data = permuted(data, IP_minus1);

            return data;
        }
    }


    private static class DesCfbModeEncryptor extends DesEncryptor {

        private final long initializationVector;


        public DesCfbModeEncryptor(long key, long initializationVector) {
            super(key);
            this.initializationVector = initializationVector;
        }

        @Override
        public long encrypt(long data) {
            return super.encrypt(data);
        }

        @Override
        public long decrypt(long data) {
            return super.decrypt(data);
        }
    }


    private static long loadKey(String path) throws Exception {
        String hexString = Files.readString(Path.of(path));
        if (hexString.length() > 14) hexString = hexString.substring(0, 14);
        return Long.parseLong(hexString, 16);
    }

    private static long loadInitialVector(String path) throws Exception {
        String hexString = Files.readString(Path.of(path));
        if (hexString.length() > 16) hexString = hexString.substring(0, 16);
        return Long.parseLong(hexString, 16);
    }

    private final static String INPUT_FILE_ARG = "--input";
    private final static String OUTPUT_FILE_ARG = "--output";
    private final static String KEY_FILE_ARG = "--key";
    private final static String INITIAL_VECTOR_FILE_ARG = "--initial-vector";
    private final static String MODE_ARG = "--mode";

    private static void executeWithArguments(String[] args) {
        if (args.length % 2 == 1) throw new IllegalArgumentException("Wrong number of arguments");

        InputStream inputStream = null;
        OutputStream outputStream = null;
        long key = 0L;
        long initialVector = 0L;
        boolean isEncrypt = true;

        for (int i = 0; i < args.length; i += 2) {
            switch (args[i]) {
                case INPUT_FILE_ARG:
                    try {
                        inputStream = new FileInputStream(args[i + 1]);
                    } catch (Exception e) {
                        throw new IllegalArgumentException("Can't open input file");
                    }
                    break;
                case OUTPUT_FILE_ARG:
                    try {
                        outputStream = new FileOutputStream(args[i + 1]);
                    } catch (Exception e) {
                        throw new IllegalArgumentException("Can't open output file");
                    }
                    break;
                case KEY_FILE_ARG:
                    try {
                        key = loadKey(args[i + 1]);
                    } catch (Exception e) {
                        throw new IllegalArgumentException("Can't load key");
                    }
                    break;
                case INITIAL_VECTOR_FILE_ARG:
                    try {
                        initialVector = loadInitialVector(args[i + 1]);
                    } catch (Exception e) {
                        throw new IllegalArgumentException("Can't load initial vector");
                    }
                    break;
                case MODE_ARG:
                    if ("encrypt".equals(args[i + 1])) isEncrypt = true;
                    else if ("decrypt".equals(args[i + 1])) isEncrypt = false;
                    else throw new IllegalArgumentException("Wrong mode (is allowed encrypt/decrypt)");
                    break;
            }
        }

        if (Objects.isNull(inputStream)) throw new IllegalArgumentException("input file is unknown");
        if (Objects.isNull(outputStream)) throw new IllegalArgumentException("output file is unknown");

        Encryptor encryptor = new DesCfbModeEncryptor(key, initialVector);
        long data = 0;
        int read;
        for (int i = 0; ; i = (i + 1) & 0b111) {
            try {
                read = inputStream.read();
            } catch (IOException e) {
                throw new RuntimeException("Problem with reading input file");
            }

            if (read == -1) {
                if (i == 0) break;
                else read = 0;
            }

            data = (data << 8L) | (read & 0xFF);

            if (i == 7) {
                data = isEncrypt ? encryptor.encrypt(data) : encryptor.decrypt(data);
                for (int j = 7; j >= 0; --j) {
                    try {
                        if (!isEncrypt && (j < 7) && ((data & ((1L << (8L * j + 8L)) - 1L)) == 0)) break;
                        outputStream.write((int) ((data >> (8L * j)) & 0xFF));
                    } catch (IOException e) {
                        throw new RuntimeException("Problem with writing output file");
                    }
                }
            }
        }
        try {
            inputStream.close();
        } catch (IOException e) {
            throw new RuntimeException("Problem with closing input file");
        }

        try {
            outputStream.close();
        } catch (IOException e) {
            throw new RuntimeException("Problem with closing output file");
        }
    }

    public static void main(String[] args) {
        try {
            executeWithArguments(args);
        } catch (RuntimeException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}

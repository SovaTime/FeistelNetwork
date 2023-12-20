package vsu.fifth;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class Main {

    public static void main(String[] args) throws IOException {

        long k = 0x123456789ABCDEF0L;
        short[] keys = generateRoundKeys(k);

        long[] data = readFile("data.txt");

        encrypt(data, keys);
        writeFile("encrypted.txt", data);
        decrypt(data, keys);

        writeFile("decrypted.txt", data);
    }

    private static short[] generateRoundKeys(long k) {
        short[] keys = new short[2];
        for (int i = 0; i < 2; i++) {
            long firstPart = Long.rotateRight(k, i * 3) >> 32;
            long secondPart = Long.rotateRight(k, i * 3) & 0xFFFFFFFFL;
            keys[i] = (short) ((firstPart ^ secondPart) >> 16);
        }
        return keys;
    }

    public static long[] readFile(String file) throws IOException {
        List<Long> chunksList = new ArrayList<>();
        int chunkSize = 8;

        try (FileInputStream fileInputStream = new FileInputStream(file);
             DataInputStream dataInputStream = new DataInputStream(fileInputStream)) {
            long value;

            while (fileInputStream.available() >= chunkSize) {
                value = dataInputStream.readLong();
                chunksList.add(value);
            }
        }

        // Преобразование списка частей в массив
        long[] chunks = new long[chunksList.size()];
        for (int i = 0; i < chunksList.size(); i++) {
            chunks[i] = chunksList.get(i);
        }

        return chunks;
    }

    public static void writeFile(String file, long[] data) throws IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(file);
             DataOutputStream dataOutputStream = new DataOutputStream(fileOutputStream)) {

            for (long value : data) {
                dataOutputStream.writeLong(value);
            }
        }
    }

    private static long cipherCBC(long bl, long vect) {
        return bl ^ vect;
    }

    private static void encrypt(long[] data, short[] keys) {

        for (int i = 0; i < data.length; i++) {
            System.out.println("Кодируемый блок  " + i);
            System.out.println(data[i]);
            if (i == 0) {
                long vector = 0x12345678;
                data[i] = cipherCBC(data[i], vector);
            } else {
                data[i] = cipherCBC(data[i], data[i - 1]);
                System.out.println("Блок xor с " + data[i - 1]);
            }
            System.out.println(data[i]);

            short m0 = (short) (data[i] >> (long) 48);
            short m1 = (short) (data[i] >> (long) 32);
            short m2 = (short) (data[i] >> (long) 16);
            short m3 = (short) data[i];

            for (short key : keys) {

                short c0 = (short) (m0 ^ rol(key, 5));
                short c1 = (short) (m1 ^ c0);
                short c2 = (short) (m2 ^ m1);
                short c3 = (short) (m3 ^ f1(m0, m1, m2, key));


                m0 = c2;
                m1 = c0;
                m2 = c3;
                m3 = c1;
            }

            int high = (m0 << 16) | (m1 & 0xFFFF);
            int low = (m2 << 16) | (m3 & 0xFFFF);
            long block = (((long)high) << 32) | (low & 0xFFFFFFFFL);
            data[i] = block;
            System.out.println("Зашифрованный блок " + i);
            System.out.println(data[i]);
            System.out.println();
        }
    }


    private static void decrypt(long[] data, short[] roundKeys) {
        for(int i = data.length - 1; i >= 0; i--) {
            System.out.println("Зашифрованный блок " + i);
            System.out.println(data[i]);
            short c0 = (short) (data[i] >> 48);
            short c1 = (short) (data[i] >> 32);
            short c2 = (short) (data[i] >> 16);
            short c3 = (short) data[i];

            for (int j = 1; j >= 0; j--) {

                short m3 = (short) (c3 ^ f1(c0, c1, c2, roundKeys[j]));
                short m2 = (short) (c2 ^ c1);
                short m0 = (short) (c0 ^ rol(roundKeys[j], 5));
                short m1 = (short) (c1 ^ m0);


                c0 = m0;
                c1 = m1;
                c2 = m2;
                c3 = m3;
            }
            int high = (c0 << 16) | (c1 & 0xFFFF);
            int low = (c2 << 16) | (c3 & 0xFFFF);
            long block = (((long)high) << 32) | (low & 0xFFFFFFFFL);

            System.out.println("Раскодированный блок " + i);
            System.out.println(block);


            if (i == 0) {
                block = cipherCBC(block, 0x12345678);

            } else {
                block = cipherCBC(block, data[i - 1]);
                System.out.println("Блок xor с " + data[i - 1]);
            }

            data[i] = block;


            System.out.println(data[i]);
            System.out.println();
        }
    }

    private static short f1(short m0, short m1, short m2, short k) {
        return (short) (ror(m0, 7) + ((m1 ^ 0xFFFF) ^ rol(m2, 5) ^ k));
    }

    private static short ror(short n, int s) {
        s %= 16;
        return  (byte)((n >> s) | (n << (8 - s)));
    }
    private static short rol(short n, int s) {
        s %= 16;
        return  (byte)((n << s) | (n >> (8 - s)));
    }
}
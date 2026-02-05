package com.pclutil;


public class DbeaverPasswordDecrypter {
    static String passwordToDecrypt = "OwEKLE4jpQ=="; //Input
    private static final byte[] PASSWORD_ENCRYPTION_KEY = "sdf@!#$verf^wv%6Fwe%$$#FFGwfsdefwfe135s$^H)dg".getBytes();
    private static final char[] S_BASE64CHAR = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
            'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
            'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
            'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
            'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', '+', '/'
    };

    private static final char S_BASE64PAD = '=';
    private static final byte[] S_DECODETABLE = new byte[128];

    static {
        for (int i = 0; i < S_DECODETABLE.length; i++)
            S_DECODETABLE[i] = Byte.MAX_VALUE;  // 127
        for (int i = 0; i < S_BASE64CHAR.length; i++) // 0 to 63
            S_DECODETABLE[S_BASE64CHAR[i]] = (byte) i;
    }

    public static void main(String[] args) throws Exception {
        DbeaverPasswordDecrypter dbeaverPasswordDecrypter = new DbeaverPasswordDecrypter();
        System.out.print(dbeaverPasswordDecrypter.decrypt(passwordToDecrypt));
    }


    public String decrypt(String encryptedString) throws Exception {
        if (encryptedString != null && !encryptedString.trim().isEmpty()) {
            try {
                byte[] e = decode(encryptedString);
                this.xorStringByKey(e);
                if (e[e.length - 2] == 0 && e[e.length - 1] == -127) {
                    return new String(e, 0, e.length - 2, "UTF8");
                } else {
                    throw new Exception("Invalid encrypted string");
                }
            } catch (Exception var3) {
                throw new Exception(var3);
            }
        } else {
            throw new IllegalArgumentException("Empty encrypted string");
        }
    }

    public static byte[] decode(String data) {
        char[] ibuf = new char[4];
        int ibufcount = 0;
        byte[] obuf = new byte[data.length() / 4 * 3 + 3];
        int obufcount = 0;
        for (int i = 0; i < data.length(); i++) {
            char ch = data.charAt(i);
            if (ch == S_BASE64PAD
                || ch < S_DECODETABLE.length && S_DECODETABLE[ch] != Byte.MAX_VALUE) {
                ibuf[ibufcount++] = ch;
                if (ibufcount == ibuf.length) {
                    ibufcount = 0;
                    obufcount += decode0(ibuf, obuf, obufcount);
                }
            }
        }
        if (obufcount == obuf.length)
            return obuf;
        byte[] ret = new byte[obufcount];
        System.arraycopy(obuf, 0, ret, 0, obufcount);
        return ret;
    }

    private static int decode0(char[] ibuf, byte[] obuf, int wp) {
        int outlen = 3;
        if (ibuf[3] == S_BASE64PAD) outlen = 2;
        if (ibuf[2] == S_BASE64PAD) outlen = 1;
        int b0 = S_DECODETABLE[ibuf[0]];
        int b1 = S_DECODETABLE[ibuf[1]];
        int b2 = S_DECODETABLE[ibuf[2]];
        int b3 = S_DECODETABLE[ibuf[3]];
        switch (outlen) {
            case 1:
                obuf[wp] = (byte) (b0 << 2 & 0xfc | b1 >> 4 & 0x3);
                return 1;
            case 2:
                obuf[wp++] = (byte) (b0 << 2 & 0xfc | b1 >> 4 & 0x3);
                obuf[wp] = (byte) (b1 << 4 & 0xf0 | b2 >> 2 & 0xf);
                return 2;
            case 3:
                obuf[wp++] = (byte) (b0 << 2 & 0xfc | b1 >> 4 & 0x3);
                obuf[wp++] = (byte) (b1 << 4 & 0xf0 | b2 >> 2 & 0xf);
                obuf[wp] = (byte) (b2 << 6 & 0xc0 | b3 & 0x3f);
                return 3;
            default:
                throw new RuntimeException("Internal Errror");
        }
    }

    private void xorStringByKey(byte[] plainBytes) {
        int keyOffset = 0;
        for (int i = 0; i < plainBytes.length; ++i) {
            byte keyChar = PASSWORD_ENCRYPTION_KEY[keyOffset];
            ++keyOffset;
            if (keyOffset >= PASSWORD_ENCRYPTION_KEY.length) {
                keyOffset = 0;
            }
            plainBytes[i] ^= keyChar;
        }
    }

}

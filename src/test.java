import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class test {

    private static final String HASH_ALGORITHM = "SHA-256";


    private static MessageDigest hasher;
    public static void main(String[] args) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException, IOException {
        hasher = MessageDigest.getInstance(HASH_ALGORITHM);
        char[] masterPw = "Test Data".toCharArray();
        byte[] data = chartoByteArr("This is byte data".toCharArray(), false);


        byte[] result = encryptData(masterPw, data);

        char[] wrongPw = "Tost Data".toCharArray();
        System.out.println("Decrypting Data");
        try {
            byte[] decrypt = decryptData(wrongPw, result);
            System.out.println(new String(decrypt));
        }
        catch(BadPaddingException e) {
            System.out.println("Bad key when decrypting");
        }
    }


        public static byte[] chartoByteArr(char[] arr, boolean wipeData) {
            CharBuffer charBuffer = CharBuffer.wrap(arr);
            ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
            byte[] byteArr = Arrays.copyOfRange(byteBuffer.array(),
                    byteBuffer.position(), byteBuffer.limit());
            Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
            if(wipeData) {
                wipeArray(arr);
            }
            return byteArr;
        }
        //secretKeySpec
        public static byte[] encryptData(char[] masterPw, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}); //this is a hardcoded IV since we can't store it
            SecretKeySpec secretKey = new SecretKeySpec(hashPw(masterPw), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encryptedData = cipher.doFinal(data);
            return encryptedData;
        }

        public static byte[] decryptData(char[] masterPw, byte[] encryptedData) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}); //this is a hardcoded IV since we can't store it
            SecretKeySpec secretKey = new SecretKeySpec(hashPw(masterPw), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            return cipher.doFinal(encryptedData);
        }

        public static void wipeArray(char[] arr) {
            Arrays.fill(arr, (char)0);
        }

        public static void wipeArray(byte[] arr) {
            Arrays.fill(arr, (byte) 0);
        }

    public static byte[] hashPw(char[] inputPw) {
        byte[] saltedBytes = chartoByteArr(inputPw, false);
        byte[] encryptedPw = hasher.digest(saltedBytes);
        wipeArray(saltedBytes);
        return encryptedPw;
    }
    }


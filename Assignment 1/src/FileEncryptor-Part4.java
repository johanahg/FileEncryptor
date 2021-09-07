import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Part 4
 * @author Erik Costlow
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());
    private static final String AES_CIPHER = "AES/CBC/PKCS5PADDING";
    private static final String BF_CIPHER = "Blowfish/CBC/PKCS5Padding";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {

        // Encrypt plaintext to ciphertext
        if (args[0].equals("enc")) {

            // input
            String algorithm = args[1];
            String key_length = args[2];
            char[] password = args[3].toCharArray();
            String plaintext = args[4];
            String ciphertext = args[5];

            // determines if the algorithm is blowfish or AES, gets correct cipher and iv byte length
            int iv_len = 0;
            String chosen_cipher = null;
            if (algorithm.equals("Blowfish")) {
                iv_len = 8;
                chosen_cipher = BF_CIPHER;
            }
            else if (algorithm.equals("AES")) {
                chosen_cipher = AES_CIPHER;
                iv_len = 16;
            }

            // generate random salt and iv
            SecureRandom sr = new SecureRandom();
            byte[] decoded_salt = new byte[128]; // 128 bytes salt recommended by NIST
            sr.nextBytes(decoded_salt);
            byte[] initVector = new byte[iv_len]; // 16 bytes iv
            sr.nextBytes(initVector);

            // Create a PBKDF2 key
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec pbeKeySpec = new PBEKeySpec(password, decoded_salt, 300000, Integer.parseInt(key_length));
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(pbeKey.getEncoded(), algorithm);
            System.out.println("Secret key is: " + Base64.getEncoder().encodeToString(pbeKey.getEncoded()));

            // Initialise cipher
            IvParameterSpec iv = new IvParameterSpec(initVector);
            Cipher cipher = Cipher.getInstance(chosen_cipher);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

            // encrypts the plaintext from plaintext.txt to ciphertext in ciphertext.enc
            try (InputStream fin = FileEncryptor.class.getResourceAsStream(plaintext);
                 OutputStream fout = Files.newOutputStream(Path.of(ciphertext));
                 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
                 }) {

                // transform algorithm and key length to bytes
                byte[] algorithm_byte = algorithm.getBytes();
                byte[] key_length_byte = ByteBuffer.allocate(4).putInt(Integer.parseInt(key_length)).array();

                // stores the iv, salt, algorithm and key length in the ciphertext file for decryption
                fout.write(algorithm_byte);
                fout.write(key_length_byte);
                fout.write(initVector);
                fout.write(decoded_salt);

                final byte[] bytes = new byte[1024];
                for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                    cipherOut.write(bytes, 0, length);
                }
            // catches input error
            } catch (IOException e) {
                LOG.log(Level.INFO, "Unable to encrypt", e);
            }

            LOG.info("Encryption finished, saved at " + ciphertext);
        }

        // decrypt ciphertext to plaintext
        else if (args[0].equals("dec")) {

            // input
            char[] password = args[1].toCharArray();
            String ciphertext = args[2];
            String plaintext = args[3];

            // initialise variables
            int key_len = 4;
            int iv_len = 0;
            String chosen_cipher = null;
            String algorithm_str = null;
            byte[] algorithm_start = new byte[3]; // 3 bytes for AES
            byte[] algorithm_end = new byte[5]; // add 5 bytes for BF
            byte[] key_length = new byte[4]; // 4 byte key length
            byte[] decoded_salt = new byte[128]; // 128 bytes salt

            // decrypts the ciphertext from ciphertext.enc to plaintext in decoded.txt
            try (InputStream encryptedData = Files.newInputStream(Path.of(ciphertext));
                 OutputStream decryptedOut = Files.newOutputStream(Path.of(plaintext))) {

                // reads the iv and decoded salt from ciphertext.enc
                encryptedData.read(algorithm_start, 0, 3);

                // gets the byte length of the algorithm and iv, and stores them in a variable
                String temp = new String(algorithm_start);
                if (temp.equals("Blo")) {
                    encryptedData.read(algorithm_end, 0, 5);
                    String algorithm_str_start = new String (algorithm_start);
                    String algorithm_str_end = new String (algorithm_end);
                    algorithm_str = algorithm_str_start.concat(algorithm_str_end);
                    chosen_cipher = BF_CIPHER;
                    iv_len = 8;
                }
                else {
                    algorithm_str = new String (algorithm_start);
                    chosen_cipher = AES_CIPHER;
                    iv_len = 16;
                }

                encryptedData.read(key_length, 0, key_len);
                byte[] initVector = new byte[iv_len]; // 16 bytes for AES, 4 bytes for Blowfish
                encryptedData.read(initVector, 0, iv_len);
                encryptedData.read(decoded_salt, 0, 128);

                // converts the algorithm to string and key length to int
                ByteBuffer byteBuffer = ByteBuffer.wrap(key_length);
                int key_length_int = byteBuffer.getInt();

                // Create a PBKDF2 key
                SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec pbeKeySpec = new PBEKeySpec(password, decoded_salt, 300000, key_length_int);
                SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
                SecretKeySpec secretKeySpec = new SecretKeySpec(pbeKey.getEncoded(), algorithm_str);

                // Initialise cipher
                IvParameterSpec iv = new IvParameterSpec(initVector);
                Cipher cipher = Cipher.getInstance(chosen_cipher);
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
                CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);

                final byte[] bytes = new byte[1024];
                for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                    decryptedOut.write(bytes, 0, length);
                }
            // catches input error
            } catch (IOException e) {
                LOG.log(Level.INFO, "Unable to encrypt", e);
            }

            LOG.info("Decryption complete, open " + plaintext);
        }

        else if (args[0].equals("info")) {
            String ciphertext = args[1];

            String algorithm_str = null;
            byte[] algorithm_start = new byte[3]; // 3 bytes for AES
            byte[] algorithm_end = new byte[5]; // add 5 bytes for BF
            byte[] key_length = new byte[4]; // 4 byte for key length

            // read input ciphertext file
            InputStream fin = Files.newInputStream(Path.of(ciphertext));
            fin.read(algorithm_start, 0 , 3);

            // gets the byte length of the algorithm and stores it in a variable
            String temp = new String(algorithm_start);
            if (temp.equals("Blo")) {
                fin.read(algorithm_end, 0, 5);
                String algorithm_str_start = new String (algorithm_start);
                String algorithm_str_end = new String (algorithm_end);
                algorithm_str = algorithm_str_start.concat(algorithm_str_end);
            }
            else {
                algorithm_str = new String (algorithm_start);
            }

            fin.read(key_length, 0, 4);

            // converts the algorithm to string and key length to int
            ByteBuffer byteBuffer = ByteBuffer.wrap(key_length);
            int key_length_int = byteBuffer.getInt();

            // prints out the information
            System.out.println(algorithm_str + " " + key_length_int);
        }
    }
}
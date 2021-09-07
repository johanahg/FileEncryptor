import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Part 1
 * @author Erik Costlow
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {

        // Encrypt plaintext to ciphertext
        if (args[0].equals("enc")) {

            // input
            String plaintext = args[1];
            String ciphertext = args[2];

            // generates a random key and iv
            SecureRandom sr = new SecureRandom();
            byte[] key = new byte[16];
            sr.nextBytes(key); // 128 bit keyd
            byte[] initVector = new byte[16];
            sr.nextBytes(initVector); // 16 bytes IV

            // encodes key and iv into base64 string
            System.out.println("Secret key is: " + Base64.getEncoder().encodeToString(key));
            System.out.println("IV is: " + Base64.getEncoder().encodeToString(initVector));

            // initialises cipher
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            // encrypts the plaintext from plaintext.txt to ciphertext in ciphertext.enc
            try (InputStream fin = FileEncryptor.class.getResourceAsStream(plaintext);
                 OutputStream fout = Files.newOutputStream(Path.of(ciphertext));
                 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
                 }) {
                final byte[] bytes = new byte[1024];
                for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                    cipherOut.write(bytes, 0, length);
                }

            // catches input errors
            } catch (IOException e) {
                LOG.log(Level.INFO, "Unable to encrypt", e);
            }

            LOG.info("Encryption finished, saved at " + ciphertext);
        }

        // decrypt ciphertext to plaintext
        else if (args[0].equals("dec")) {

            // decodes encoded key and iv input to bytes
            byte[] decoded_key = Base64.getDecoder().decode(args[1]);
            byte[] decoded_iv = Base64.getDecoder().decode(args[2]);
            String ciphertext = args[3];
            String plaintext = args[4];

            // initialises iv
            IvParameterSpec iv = new IvParameterSpec(decoded_iv);
            SecretKeySpec skeySpec = new SecretKeySpec(decoded_key, ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            System.out.println("Key and init vector decoded");

            // decrypts the ciphertext from ciphertext.enc to plaintext in decoded.txt
            try (InputStream encryptedData = Files.newInputStream(Path.of(ciphertext));
                 CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                 OutputStream decryptedOut = Files.newOutputStream(Path.of(plaintext))) {
                final byte[] bytes = new byte[1024];
                for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                    decryptedOut.write(bytes, 0, length);
                }
            // catches input errors
            } catch (IOException ex) {
                Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
            }

            LOG.info("Decryption complete, open " + plaintext);
        }
    }
}

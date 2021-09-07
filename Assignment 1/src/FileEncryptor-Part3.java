import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
 *
 * @author Erik Costlow
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {

        // Encrypt plaintext to ciphertext
        if (args[0].equals("enc")) {

            // input
            char[] password = args[1].toCharArray();
            String plaintext = args[2];
            String ciphertext = args[3];

            // Initialise salt and iv
            SecureRandom sr = new SecureRandom();
            byte[] decoded_salt = new byte[128]; // 128 bytes salt recommended by NIST
            sr.nextBytes(decoded_salt);
            byte[] initVector = new byte[16]; // 16 bytes iv
            sr.nextBytes(initVector);

            // Create a PBKDF2 key
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec pbeKeySpec = new PBEKeySpec(password, decoded_salt, 300000, 128);
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);
            System.out.println("Secret key is: " + Base64.getEncoder().encodeToString(pbeKey.getEncoded()));

            // Initialise cipher
            IvParameterSpec iv = new IvParameterSpec(initVector);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

            // encrypts the plaintext from plaintext.txt to ciphertext in ciphertext.enc
            try (InputStream fin = FileEncryptor.class.getResourceAsStream(plaintext);
                 OutputStream fout = Files.newOutputStream(Path.of(ciphertext));
                 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
                 }) {

                // stores the iv and salt in the ciphertext file for decryption
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

            byte[] decoded_salt = new byte[128]; // 128 bytes salt
            byte[] initVector = new byte[16]; // 16 bytes iv

            // decrypts the ciphertext from ciphertext.enc to plaintext in decoded.txt
            try (InputStream encryptedData = Files.newInputStream(Path.of(ciphertext));
                 OutputStream decryptedOut = Files.newOutputStream(Path.of(plaintext))) {

                // reads the iv and decoded salt from ciphertext.enc
                encryptedData.read(initVector, 0, 16);
                encryptedData.read(decoded_salt, 0, 128);

                // Create a PBKDF2 key
                SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec pbeKeySpec = new PBEKeySpec(password, decoded_salt, 300000, 128);
                SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
                SecretKeySpec secretKeySpec = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);

                // Initialise cipher
                IvParameterSpec iv = new IvParameterSpec(initVector);
                Cipher cipher = Cipher.getInstance(CIPHER);
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
                System.out.println("Key and init vector decoded");
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
    }
}
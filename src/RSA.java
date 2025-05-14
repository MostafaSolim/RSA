import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.io.IOException;

public class RSA {
    public class Converter {

        // Converts a text string (ASCII-only) to a BigInteger
        public static BigInteger stringToBigInteger(String message) {
            byte[] bytes = message.getBytes(StandardCharsets.US_ASCII); // turns each char into its ASCII NR
            return new BigInteger(1, bytes); // The '1' means non-negative
        }

        // Converts a BigInteger back to a text string (ASCII-only)
        public static String bigIntegerToString(BigInteger bigInt) {
            byte[] bytes = bigInt.toByteArray();
            // Remove leading zero byte (if present) added by positive BigInteger representation
            if (bytes.length > 1 && bytes[0] == 0) {
                // Copy bytes[1..end] to a new array
                byte[] tmp = new byte[bytes.length - 1];
                System.arraycopy(bytes, 1, tmp, 0, tmp.length);
                bytes = tmp;
            }
            return new String(bytes, StandardCharsets.US_ASCII);
        }
    }

    public static void main(String[] args) throws IOException {

        SecureRandom random = new SecureRandom();
        int bitLength = 128; // Each prime is 128 bits

        BigInteger p = BigInteger.probablePrime(bitLength, random); // Generate a random prime number for p
        BigInteger q = BigInteger.probablePrime(bitLength, random); // Generate a random prime number for q
        BigInteger n = p.multiply(q); // n = p * q
        BigInteger QM1 = q.subtract(BigInteger.ONE); // q-1
        BigInteger PM1 = p.subtract(BigInteger.ONE); // p-1
        BigInteger Fn= (PM1).multiply(QM1); // Fn = (p-1)(q-1)
        System.out.println("Bit length of n: " + n.bitLength()); // Should be >= 256
        BigInteger e=BigInteger.valueOf(65537); // Commonly used public exponent
        if (e.gcd(Fn)!=BigInteger.valueOf(1)) { // If e is not coprime with Fn, find the next possible e
            for(BigInteger i=BigInteger.valueOf(2);!i.equals(Fn) ;i=i.add(BigInteger.ONE)) { // For every i from 2 to Fn
                if ((i.gcd(Fn)).equals(BigInteger.ONE)) { // If i is coprime with Fn
                    e=i; //biggest possible e
                    break;
                }
            }
        }
        BigInteger d=e.modInverse(Fn);

        // Read the file Message.txt
        // Get the path to the same folder as this Java file
        Path currentDir = Paths.get("src", RSA.class.getPackage().getName().replace('.', '/')).toAbsolutePath();

        // Read the file Message.txt
        Path messagePath = currentDir.resolve("Message.txt");
        String message = new String(Files.readAllBytes(messagePath), StandardCharsets.UTF_8);

        // Encrypt the file content
        BigInteger messageBI = Converter.stringToBigInteger(message);
        BigInteger encryptedMessage = messageBI.modPow(e, n);

        // Write encrypted content to encrypted.txt
        Path encryptedPath = currentDir.resolve("encrypted.txt");
        Files.write(encryptedPath, encryptedMessage.toString().getBytes(StandardCharsets.UTF_8));

        // Decrypt the encrypted content
        BigInteger decryptedMessage = encryptedMessage.modPow(d, n);
        String decryptedText = Converter.bigIntegerToString(decryptedMessage);

        // Write decrypted content to decrypted.txt
        Path decryptedPath = currentDir.resolve("decrypted.txt");
        Files.write(decryptedPath, decryptedText.getBytes(StandardCharsets.UTF_8));

        System.out.println("The generated public key in plaintext:"+ Converter.bigIntegerToString(e));
        System.out.println("The generated public key in BigInt:"+ e);
        System.out.println("The generated private key in plaintext:"+ Converter.bigIntegerToString(d));
        System.out.println("The generated private key in BigInt:"+ d);
        System.out.println("Message in plaintext: "+ message);
        System.out.println("Message in bigInt : "+ Converter.stringToBigInteger(message));
        System.out.println("Encrypted Cipher in Plaintext:"+Converter.bigIntegerToString(encryptedMessage));
        System.out.println("Encrypted Cipher in bigInt:"+encryptedMessage);
        System.out.println("Decrypted Message in Plaintext:"+decryptedText);
        System.out.println("Encrypted Cipher in bigInt:"+Converter.stringToBigInteger(decryptedText));

        System.out.println("Encryption and Decryption complete.");
    }
}
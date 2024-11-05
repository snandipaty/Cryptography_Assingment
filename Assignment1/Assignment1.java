import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.util.Arrays;

public class Assignment1 {
    // Initialization constants
    private static final String P_init = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
    private static final String G_init = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
    private static final String A_init = "5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d";

    private static final BigInteger P = new BigInteger(P_init, 16);
    private static final BigInteger G = new BigInteger(G_init, 16);
    private static final BigInteger A = new BigInteger(A_init, 16);

    public static void main(String[] args) throws Exception {
        // Diffie-Hellman key exchange
        BigInteger[] dhResult = DiffieHellman();
        BigInteger B = dhResult[0];  // Public value B
        BigInteger s = dhResult[1];  // Shared secret s

        // Generate AES key
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(s.toByteArray());
        SecretKeySpec aesKey = new SecretKeySpec(keyBytes, "AES");

        // Generate IV
        byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // Encrypt the input file
        String inputFile = args[0];
        byte[] encryptedData = encryptFile(inputFile, aesKey, iv);

        // Write results to files
        writeHexToFile("DH.txt", B.toByteArray());
        writeHexToFile("IV.txt", ivBytes);
        System.out.println(bytesToHex(encryptedData));
    }

    //Diffie Hellman
    private static BigInteger[] DiffieHellman() {
        SecureRandom random = new SecureRandom();
        BigInteger b = new BigInteger(1023, random);  // Secret value b
        BigInteger B = modExp(G, b, P);               // Public value B = G^b mod P
        BigInteger s = modExp(A, b, P);               // Shared secret s = A^b mod P
        return new BigInteger[]{B, s};
    }

    //Encrypting the file using AES in CBC mode
    private static byte[] encryptFile(String inputFile, SecretKeySpec key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] inputBytes = padFile(readFile(inputFile));
        return cipher.doFinal(inputBytes);
    }

    //Function for padding 
    private static byte[] padFile(byte[] data) {
        int blockSize = 16;
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] padded = Arrays.copyOf(data, data.length + paddingLength);
        padded[data.length] = (byte) 0x80;  // Add padding
        return padded;
    }

    //reading the file
    private static byte[] readFile(String filename) throws IOException {
        return Files.readAllBytes(new File(filename).toPath());
    }

    //writing to the file
    private static void writeHexToFile(String filename, byte[] data) throws IOException {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(bytesToHex(data));
        }
    }

    //changing the bytes to hexidecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    //Modular exponentiation algorithm
    private static BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
        BigInteger result = BigInteger.ONE;
        base = base.mod(mod);
        while (exp.signum() > 0) {
            if (exp.testBit(0)) {
                result = result.multiply(base).mod(mod);
            }
            base = base.multiply(base).mod(mod);
            exp = exp.shiftRight(1);
        }
        return result;
    }
}




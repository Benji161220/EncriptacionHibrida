import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

public class HybridEncryptionExample {
    public static void main(String[] args) throws Exception{
        Scanner sc = new Scanner(System.in);
        System.out.println("Ingrese el mensaje a cifrar");
        String mensaje = sc.nextLine();

        String clavePersonalizada = "claveSecreta1234";

        byte[] claveBytes = clavePersonalizada.getBytes();

        SecretKey secretKey = new SecretKeySpec(claveBytes, "AES");

        byte[] encryptedMessage = encrypt(mensaje, secretKey);

        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] claveCifrada = cifrarConRSA(clavePersonalizada.getBytes(), publicKey);

        System.out.println("Mensaje cifrado: " + Base64.getEncoder().encodeToString(encryptedMessage));
        System.out.println("Clave cifrada: " + Base64.getEncoder().encodeToString(claveCifrada));
        byte[] claveDescifrada = descifrarConRSA(claveCifrada, privateKey);
        String decryptedMessage = decrypt(encryptedMessage, new SecretKeySpec(claveDescifrada, "AES"));
        System.out.println("Mensaje descifrado: " + decryptedMessage);


    }
    public static byte[] encrypt(String message, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(message.getBytes());
    }
    private static byte[] cifrarConRSA(byte[] datos, PublicKey clavePublica) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, clavePublica);
        return cipher.doFinal(datos);
    }

    private static byte[] descifrarConRSA(byte[] datosCifrados, PrivateKey clavePrivada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, clavePrivada);
        return cipher.doFinal(datosCifrados);
    }
    public static String decrypt(byte[] encryptedMessage, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }
}

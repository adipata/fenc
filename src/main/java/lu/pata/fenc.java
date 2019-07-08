package lu.pata;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.spec.KeySpec;
import java.util.Base64;

public class fenc {
    static Logger log = LoggerFactory.getLogger(fenc.class);

    public static void main(String[] args) throws IOException {
        secretKey=args[1];
        salt=args[2];
        if(args[0].equals("e")){
            log.info("Encrypt");
            File f=new File(args[3]);
            byte[] data= Files.readAllBytes(f.toPath());
            try (PrintWriter out = new PrintWriter("enc.txt")) {
                out.print(encrypt(data));
            }
        } else {
            log.info("Decrypt");
            File f=new File(args[3]);
            String content = Files.readString(f.toPath());
            try (FileOutputStream stream = new FileOutputStream("dec.txt")) {
                stream.write(decrypt(content));
            }
        }
    }

    private static String secretKey;
    private static String salt;

    private static String encrypt(byte[] data)
    {
        return Base64.getEncoder().encodeToString(process(data,Cipher.ENCRYPT_MODE));
    }

    private static byte[] decrypt(String data)
    {
        return process(Base64.getDecoder().decode(data),Cipher.DECRYPT_MODE);
    }

    private static byte[] process(byte[] data,int mode){
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(mode, secretKey, ivspec);

            return cipher.doFinal(data);
        } catch (Exception ex){
            log.error("Error while processing: " + ex.toString());
            return null;
        }
    }
}

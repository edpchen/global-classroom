package security_client;

import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
//import seguridad20222_servidor.SecurityFunctions;

public class ClientMain {
  public static void main(String[] args) throws Exception {
    PublicKey publicKey = null;
    PrintWriter out = null;
    BufferedReader in = null;
    //create socket & connect to server
    Socket clientSocket = new Socket("localhost",4030);
    //get our output stream for writing to
    out = new PrintWriter(clientSocket.getOutputStream(),true);
    //get server input stream (bytes->characters -> buffer);
    in = new BufferedReader(
      new InputStreamReader(clientSocket.getInputStream()));

    System.out.println("connected to server");
    publicKey = readPublicKey("datos_asim_srv.pub");
    System.out.println("got public key");

    //start communication
    out.println("SECURE INIT");

    //get G, P, G^x from server
    String G_str = in.readLine();
    BigInteger g = new BigInteger(G_str);
    System.out.println("G: " + G_str);
    String P_str = in.readLine();
    BigInteger p = new BigInteger(P_str);
    System.out.println("P: " + P_str);
    String Gx_str = in.readLine();
    BigInteger gx = new BigInteger(Gx_str);
    System.out.println("G^x: " + Gx_str);

    //verify signature
    String signature_str = in.readLine();
    System.out.println("signature: " + signature_str);
    String GPGx_str = G_str + "," + P_str + "," + Gx_str;
    if(checkSignature(publicKey,str2byte(signature_str),GPGx_str)) {
      out.println("OK");
      System.out.println("signature is correct");
    } else {
      out.println("ERROR");
      System.out.println("signature is wrong");
      clientSocket.close();
      System.exit(1);
    }

    //generate Y
    SecureRandom r = new SecureRandom();
    int y_int = Math.abs(r.nextInt());
    BigInteger y = BigInteger.valueOf(Long.valueOf(y_int));

    //compute g^y, send it
    BigInteger gy = g.modPow(y,p);
    String gy_str = gy.toString();
    System.out.println("G^y: "+gy_str);
    out.println(gy_str);

    //compute g^{xy} and the session,mac keys it creates
    BigInteger gxy = gx.modPow(y,p);
    String gxy_str = gxy.toString();
    System.out.println("G^xy: "+gxy_str);
    SecretKey sessionKey = makeSessionKey(gxy_str);
    SecretKey macKey = makeMACKey(gxy_str);

    //create the request
    int req = 9;
    byte[] req_bytes = Integer.toString(req).getBytes();

    //generate the nonce
    byte[] iv_bytes = generateIVBytes();
    String iv_str = byte2str(iv_bytes);
    IvParameterSpec iv = new IvParameterSpec(iv_bytes);
    System.out.println("request: "+req);

    //encrypt the req with the session key and iv, send it
    byte[] encReq = symmEncrypt(req_bytes,sessionKey,iv);
    String encReq_str = byte2str(encReq);
    System.out.println("encrypted request: "+encReq_str);
    out.println(encReq_str);

    //hmac the session key, send that
    byte[] mac = hmac(req_bytes,macKey);
    String mac_str = byte2str(mac);
    System.out.println("mac: "+mac_str);
    out.println(mac_str);

    //send the nonce
    System.out.println("iv: "+iv_str);
    out.println(iv_str);

    //receive the server's responses
    String okay = in.readLine();
    String encResp_str = in.readLine();
    String respMac_str = in.readLine();
    String respIv_str = in.readLine();
    System.out.println("ok/error: "+okay);
    System.out.println("encrypted resp: "+encResp_str);
    System.out.println("resp mac: "+respMac_str);
    System.out.println("reponse IV: "+respIv_str);

    //decrypt server's response
    IvParameterSpec respIv = new IvParameterSpec(str2byte(respIv_str));
    byte[] resp_bytes = symmDecrypt(str2byte(encResp_str),sessionKey,respIv);
    int resp = Integer.parseInt(new String(resp_bytes,StandardCharsets.UTF_8));
    System.out.println("response: "+resp);

    //verify server's HMAC
    if(verifyMAC(resp_bytes,macKey,str2byte(respMac_str))) {
      out.println("OKAY");
    } else {
      out.println("ERROR");
    }

    //exit
    clientSocket.close();
    System.exit(1);
  }




  /*temp, just copied SecurityFunctions's methods*/

  //read_kplus
  static PublicKey readPublicKey(String keyArchive) throws Exception {
    PublicKey key = null;
    FileInputStream stream = new FileInputStream(keyArchive);
    byte[] bytes = new byte[(int)(new File(keyArchive)).length()];
    stream.read(bytes);
    stream.close();
    KeyFactory factory = KeyFactory.getInstance("RSA");
    return factory.generatePublic(new X509EncodedKeySpec(bytes));
  }

  //checkSignature
 static boolean checkSignature(PublicKey key, byte[] signature, String m) throws Exception {
    Signature publicSignature = Signature.getInstance("SHA256withRSA");
    publicSignature.initVerify(key);
    publicSignature.update(m.getBytes(StandardCharsets.UTF_8));
    return publicSignature.verify(signature);
  }

  //csk1, use first half of seed/key
  static SecretKey makeSessionKey(String seed) throws Exception {
    byte[] byte_seed = seed.trim().getBytes(StandardCharsets.UTF_8);
    byte[] hash = MessageDigest.getInstance("SHA-512").digest(byte_seed);
    byte[] hash_32 = new byte[32];
    for(int i = 0; i < 32; i++) {
      hash_32[i] = hash[i];
    }
    return new SecretKeySpec(hash_32,"AES");
  }
  //csk2, use 2nd half of seed/key
  static SecretKey makeMACKey(String seed) throws Exception {
    byte[] byte_seed = seed.trim().getBytes(StandardCharsets.UTF_8);
    byte[] hash = MessageDigest.getInstance("SHA-512").digest(byte_seed);
    byte[] hash_32 = new byte[32];
    for(int i = 32; i < 64; i++) {
      hash_32[i-32] = hash[i];
    }
    return new SecretKeySpec(hash_32,"AES");
  }

  //senc
  static byte[] symmEncrypt(byte[] m, SecretKey k, IvParameterSpec iv) throws Exception {
    Cipher encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
    encryptor.init(Cipher.ENCRYPT_MODE, k, iv);
    byte[] c = encryptor.doFinal(m);
    return c;
  }
  //sdec
  static byte[] symmDecrypt(byte[] c, SecretKey k, IvParameterSpec iv) throws Exception {
    Cipher decryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
    decryptor.init(Cipher.DECRYPT_MODE, k, iv);
    byte[] m = decryptor.doFinal(c);
    return m;
  }
  //hmac
  static byte[] hmac(byte[] m, SecretKey k) throws Exception {
    Mac mac = Mac.getInstance("HMACSHA256");
    mac.init(k);
    return mac.doFinal(m);
  }
  static boolean verifyMAC(byte[] m, SecretKey k, byte[] mac) throws Exception {
    byte[] mac_o = hmac(m,k);
    if(mac_o.length != mac.length) {
      return false;
    }
    for(int i = 0; i < mac_o.length; i++) {
      if(mac_o[i] != mac[i]) {
        return false;
      }
    }
    return true;
  }

  //from SrvThread
  static byte[] str2byte(String s) {
    byte[] b = new byte[s.length()/2];
    for(int i = 0; i < b.length; i++) {
      b[i] = (byte) Integer.parseInt(s.substring(i*2,(i+1)*2),16);
    }
    return b;
  }
  static String byte2str(byte[] b) {
    String s = "";
    for(int i = 0; i < b.length; i ++) {
      char b_i = (char)b[i];
      String g = Integer.toHexString( b_i & 0x00ff );
      s += (g.length() == 1 ? "0" : "") + g;
    }
    return s;
  }
  static byte[] generateIVBytes() {
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    return iv;
  }
}

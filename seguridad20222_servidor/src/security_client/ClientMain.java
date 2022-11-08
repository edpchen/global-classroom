package security_client;

import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
//import javax.crypto.*;
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
    
    out.println("SECURE INIT");//start connection
    
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
    BigInteger Gy = g.modPow(y,p);
    System.out.printf("G^y: "+Gy.toString());
    out.println(Gy.toString());
  

  }
  //temp, just copied SecurityFunctions's methods
  static PublicKey readPublicKey(String keyArchive) throws Exception {
    PublicKey key = null;
    FileInputStream stream = new FileInputStream(keyArchive);
    byte[] bytes = new byte[(int)(new File(keyArchive)).length()];
    stream.read(bytes);
    stream.close();
    KeyFactory factory = KeyFactory.getInstance("RSA");
    key = factory.generatePublic(
      new X509EncodedKeySpec(bytes));
    return key;
  }
 static boolean checkSignature(PublicKey key, byte[] signature, String m) throws Exception {
    Signature publicSignature = Signature.getInstance("SHA256withRSA");
    publicSignature.initVerify(key);
    publicSignature.update(m.getBytes(StandardCharsets.UTF_8));
    return publicSignature.verify(signature);
  }

  //from SrvThread
  static byte[] str2byte(String s) {
    byte[] b = new byte[s.length()/2];
    for(int i = 0; i < b.length; i++) {
      b[i] = (byte) Integer.parseInt(s.substring(i*2,(i+1)*2),16);
    }
    return b;
  }
}

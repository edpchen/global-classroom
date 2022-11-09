package security_client;

public class ClientMain {
  public static void main(String[] args) throws Exception {
    int no = 1;
    if(args != null && args.length > 0) {
      no = Integer.parseInt(args[0]);
    }
    for(int i = 0; i < no; i++) {
      ClientThread t = new ClientThread();
      t.start();
    }
  }
}

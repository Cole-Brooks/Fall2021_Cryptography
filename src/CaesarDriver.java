import java.util.Scanner;

public class CaesarDriver {
    public static void main(String[] args){

        boolean quit = false;
        Scanner scnr = new Scanner(System.in);

        while(!quit){
            System.out.println("Welcome to the java Caesar shifter. Type quit to quit the program. Else, type your message");

            String message = scnr.nextLine();

            if(message == "quit"){
                quit = true;
            }
            else{
                String encryptOrDecrypt = "INVALID STRING";
                while(!encryptOrDecrypt.equals("e") && !encryptOrDecrypt.equals("d")){
                    System.out.println("Encrypt (type 'e') or Decrypt (type 'd')");
                    encryptOrDecrypt = scnr.nextLine();
                }
                boolean encrypt = encryptOrDecrypt.equals("e");

                System.out.println("Finally, input a key from 0-25");
                int key = scnr.nextInt();

                System.out.println(CaesarShifter.shiftMessage(message, key, encrypt));
                quit = true;
            }
        }
    }
}

public class CaesarShifter {
    final static String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static String shiftMessage(String message, int key){
        return shiftMessage(message, key, true);
    }

    public static String shiftMessage(String message, int key, boolean encrypt){
        // start off by checking the key for correctness
        if(key < 0){
            return "you may not have a negative key";
        }
        else if(key > 25){
            key = key % 25;
        }

        char[] encryptedMessage = new char[message.length()];

        for(int i = 0; i < message.length(); i++){
            char curChar = message.charAt(i);
            int curCharIndex = alphabet.indexOf(Character.toUpperCase(curChar));

            if(curChar == ' '){
                // don't do anything to spaces for a ceasar cipher
                encryptedMessage[i] = curChar;
            }
            else if(curCharIndex != -1){
                // if the current character is in the alphabet, we need to shift it
                if(encrypt){
                    // shift right if encrypting, left if decrypting
                    encryptedMessage[i] = alphabet.charAt( (curCharIndex + key) % 26 );
                }
                else{
                    if(curCharIndex - key < 0){
                        encryptedMessage[i] = alphabet.charAt( 26 + (curCharIndex - key) );
                    }
                    else {
                        encryptedMessage[i] = alphabet.charAt(curCharIndex - key);
                    }
                }
            }
            else{
                // an unknown character has been encountered. Report error to user
                return "Error: This encryptor may only be used for the English alphabet.";
            }
        }

        return new String(encryptedMessage);
    }
}

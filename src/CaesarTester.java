import java.util.ArrayList;

public class CaesarTester {
    public static void main(String[] args){
        String[] testStrings = new String[3];
        testStrings[0] = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG";
        testStrings[1] = "THIS IS A VERY LONG SENTENCE THAT SEEMS TO GO ON FOREVER AND EVER WITH NO END IN SIGHT ITS A WONDER THAT ANYONE CAN EVEN READ IT";
        testStrings[2] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        boolean success = true;
        boolean verbose = false;
        ArrayList<Integer> failures = new ArrayList<Integer>();

        for (String testString : testStrings) {
            for (int k = 0; k < 1; k++) {
                success = success && (testString.equals(CaesarShifter.shiftMessage(CaesarShifter.shiftMessage(testString, k), k, false)));
                if(!success){
                    failures.add(k);
                    if(verbose){
                        System.out.print("Expected: ");
                        System.out.println(testString);
                        System.out.print("Encrypted: ");
                        System.out.println(CaesarShifter.shiftMessage(testString, k));
                        System.out.print("Actual: ");
                        System.out.println(CaesarShifter.shiftMessage(CaesarShifter.shiftMessage(testString, k), k, false));
                    }
                }
            }
        }

        if(success){
            System.out.println("All tests passed successfully");
        }
        else{
            System.out.println("ERROR: Some tests have failed...");
            System.out.println(failures);
        }
    }
}

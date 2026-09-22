import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Dictionary attack (brute-force from a file) against a LOCAL, simulated target.
 *
 * <p>The target ({@link LoginTarget}) lives inside this project and only answers
 * true/false to an authentication attempt; it never touches the network or any
 * real account.
 *
 * <p>This class reads candidate passwords line by line from a wordlist file
 * (default {@code wordlist.txt}, or the path given as the first argument),
 * skipping blank lines and lines starting with '#'. Each candidate is tried
 * against the target until one matches or the file ends. Finally it prints
 * whether the password was found, how many attempts it took, and how long it ran.
 *
 * <p>Usage:
 * <pre>
 *   java DictionaryAttack                 // uses wordlist.txt
 *   java DictionaryAttack other_list.txt  // a different file
 * </pre>
 *
 * <p>Educational only: use this technique solely on your own systems or where
 * you have written authorization.
 */
public class DictionaryAttack {

    public static void main(String[] args) throws IOException {
        String username = "admin";
        String secret = "sunshine";
        LoginTarget target = new LoginTarget(username, secret);

        Path wordlist = Paths.get(args.length > 0 ? args[0] : "wordlist.txt");
        if (!Files.exists(wordlist)) {
            System.err.println("File not found: " + wordlist.toAbsolutePath());
            System.err.println("Create a wordlist.txt with one password per line.");
            return;
        }

        System.out.println("Target: user '" + username + "' (simulated local login)");
        System.out.println("Wordlist: " + wordlist.toAbsolutePath());
        System.out.println("----------------------------------------");

        long start = System.nanoTime();
        String found = null;

        try (BufferedReader br = Files.newBufferedReader(wordlist, StandardCharsets.UTF_8)) {
            String candidate;
            while ((candidate = br.readLine()) != null) {
                candidate = candidate.strip();
                if (candidate.isEmpty() || candidate.startsWith("#")) {
                    continue;
                }
                if (target.authenticate(username, candidate)) {
                    found = candidate;
                    break;
                }
            }
        }

        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        System.out.println();
        if (found != null) {
            System.out.println("=========================================");
            System.out.println("  PASSWORD FOUND: " + found);
            System.out.println("=========================================");
        } else {
            System.out.println("Password NOT found in the wordlist.");
        }
        System.out.println("Attempts made : " + target.getAttempts());
        System.out.println("Time          : " + elapsedMs + " ms");
    }
}

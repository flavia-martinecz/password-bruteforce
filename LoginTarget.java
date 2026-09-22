import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Simulated "login server" — lives inside the project, NOT on the network.
 *
 * Holds a single (username, password) pair. The password is never stored in
 * clear text: only the SHA-256 hash of (random salt + password) is kept, just
 * like a real system does, so authenticate() can verify an attempt but can
 * never recover the password from the hash. It answers only true/false, counts
 * how many attempts were made (to measure the "cost" of an attack), and compares
 * hashes in constant time so no information leaks through timing.
 */
public class LoginTarget {

    private final String username;
    private final byte[] salt;
    private final byte[] passwordHash;

    private long attempts = 0;

    public LoginTarget(String username, String secretPassword) {
        this.username = username;
        this.salt = new byte[16];
        new SecureRandom().nextBytes(this.salt);
        this.passwordHash = hash(this.salt, secretPassword);
    }

    public boolean authenticate(String user, String passwordGuess) {
        attempts++;
        if (!this.username.equals(user)) {
            return false;
        }
        byte[] guessHash = hash(this.salt, passwordGuess);
        return constantTimeEquals(this.passwordHash, guessHash);
    }

    public long getAttempts() {
        return attempts;
    }

    private static byte[] hash(byte[] salt, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            md.update(password.getBytes(StandardCharsets.UTF_8));
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
}

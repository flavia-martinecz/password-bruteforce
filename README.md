# Password Brute-Force Lab

A small, self-contained Java project that demonstrates a **dictionary attack**
(a form of brute-forcing) against a **simulated, local login**. Nothing here
touches the network, a website, or a real account: the "target" is a class that
lives inside the project. The goal is purely educational — to _understand_ how
password guessing works so you can _defend_ against it.

---

## Table of contents

1. [What is brute-forcing?](#1-what-is-brute-forcing)
2. [Project structure](#2-project-structure)
3. [Code walkthrough](#3-code-walkthrough)
4. [Build and run](#4-build-and-run)
5. [Sample output](#5-sample-output)
6. [Experiments to try](#6-experiments-to-try)
7. [How real systems defend against this](#7-how-real-systems-defend-against-this)
8. [Ethics and legal note](#8-ethics-and-legal-note)
9. [License](#9-license)

---

## 1. What is brute-forcing?

**Brute-forcing** is an attack that finds a secret (usually a password) by
_trying candidates one after another_ until one works. It relies on no clever
trick — only on the fact that a computer can test guesses very fast.

There are three common flavours:

| Type                  | How candidates are produced                                                    | Notes                                                                                                  |
| --------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| **Pure brute-force**  | Every possible combination of characters (`a`, `b`, ..., `aa`, `ab`, ...)      | Guaranteed to find the password _eventually_, but the number of tries explodes with length.            |
| **Dictionary attack** | Read from a list of likely passwords (a _wordlist_)                            | Fast and very effective because most people reuse common passwords. **This project uses this method.** |
| **Hybrid attack**     | Words from a list plus small mutations (`password` -> `password1`, `p@ssword`) | Combines the speed of a dictionary with some of the coverage of pure brute-force.                      |

### The math: why length beats everything

For pure brute-force, the number of possible passwords (the _keyspace_) is:

```
keyspace = (size of character set) ^ (password length)
```

Example, lowercase letters only (26 characters):

| Length | Combinations (26^length) |
| -----: | ------------------------ |
|      3 | 17 576                   |
|      4 | 456 976                  |
|      6 | ~308 million             |
|      8 | ~208 billion             |

Add uppercase, digits and symbols (~95 printable characters) and an 8-character
password already has ~6.6 _quadrillion_ combinations. Every extra character
multiplies the work, which is why **length is the single most important factor**
in password strength.

### Why dictionary attacks work so well

Pure brute-force of a long password is infeasible — but most passwords are _not_
random. People pick `123456`, `password`, a pet name, a favourite team. A
dictionary attack skips the astronomically large keyspace and only tries the few
thousand passwords people _actually_ use. If your password is on that list, the
length no longer protects you: it falls in milliseconds. That is the exact
lesson this project makes visible.

---

## 2. Project structure

```
password-generator/
├── LoginTarget.java       # the simulated login system (the "victim")
├── DictionaryAttack.java  # the attacker: reads the wordlist and guesses
├── wordlist.txt           # the list of candidate passwords, one per line
├── nomatch.txt            # a tiny list that does NOT contain the secret (demo)
├── .gitignore             # keeps compiled *.class files out of git
├── LICENSE                # MIT license
└── README.md              # this file
```

| File                    | Role                                                                                                                                     |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `LoginTarget.java`      | A stand-in for a real login server. It stores one username and the **hash** of one password, and answers only `true`/`false` to a guess. |
| `DictionaryAttack.java` | The program you run. It opens the wordlist, tries each entry against the target, and reports the result and statistics.                  |
| `wordlist.txt`          | 120 of the most common real-world passwords, one per line. Lines starting with `#` are comments.                                         |
| `nomatch.txt`           | A 5-entry list used in [Sample output](#5-sample-output) Example 2 to show a run where the password is **not** found.                     |
| `LICENSE`               | The MIT license text (see [License](#9-license)).                                                                                        |

---

## 3. Code walkthrough

### `LoginTarget.java` — the target

This class models how a _responsible_ login system stores a password. Two ideas
matter:

- **It never stores the password in clear text.** In the constructor it
  generates a random 16-byte _salt_ and computes `SHA-256(salt + password)`,
  keeping only that hash:

  ```java
  this.salt = new byte[16];
  new SecureRandom().nextBytes(this.salt);
  this.passwordHash = hash(this.salt, secretPassword);
  ```

  A hash is a one-way function: you can compute it from the password, but you
  cannot reverse it to recover the password. The **salt** is random data mixed
  in so that two users with the same password get different hashes — this
  defeats precomputed "rainbow table" lookups.

- **It only answers yes/no.** The single public method verifies a guess by
  hashing it the same way and comparing:

  ```java
  public boolean authenticate(String user, String passwordGuess) {
      attempts++;
      if (!this.username.equals(user)) return false;
      byte[] guessHash = hash(this.salt, passwordGuess);
      return constantTimeEquals(this.passwordHash, guessHash);
  }
  ```

  The comparison uses `constantTimeEquals`, which always inspects every byte
  instead of returning early on the first mismatch. This prevents a _timing
  attack_, where an attacker measures tiny response-time differences to learn
  the password one byte at a time. The `attempts` counter simply records how
  much work the attacker had to do.

### `DictionaryAttack.java` — the attacker

The `main` method does four things:

1. **Set up the target.** It creates a `LoginTarget` with a username and a
   secret password. Change `secret` to experiment (see below):

   ```java
   String username = "admin";
   String secret = "sunshine";
   LoginTarget target = new LoginTarget(username, secret);
   ```

2. **Open the wordlist.** It defaults to `wordlist.txt`, or uses the file path
   you pass as the first command-line argument.

3. **Try each candidate.** It reads the file _line by line_ (so a huge wordlist
   never has to fit in memory at once), skips blank lines and comments, and
   calls `authenticate` on each candidate until one matches or the file ends:

   ```java
   while ((candidate = br.readLine()) != null) {
       candidate = candidate.strip();
       if (candidate.isEmpty() || candidate.startsWith("#")) continue;
       if (target.authenticate(username, candidate)) { found = candidate; break; }
   }
   ```

4. **Report.** It prints whether the password was found, how many attempts it
   took (read from the target via `target.getAttempts()`), and how long it ran.

### `wordlist.txt` — the ammunition

A plain-text list of the passwords that appear at the top of real breach
datasets (`123456`, `password`, `qwerty`, ...). In a real engagement this file
might contain millions of entries; here it holds 120 so the demo runs instantly.

---

## 4. Build and run

You need a JDK (Java 11 or newer — the code uses `String.strip()`).

```bash
javac LoginTarget.java DictionaryAttack.java
java DictionaryAttack
```

Run against a different wordlist:

```bash
java DictionaryAttack my_other_list.txt
```

---

## 5. Sample output

### Example 1 — password found

With the defaults (`secret = "sunshine"`, which sits at line 40 of
`wordlist.txt`), running `java DictionaryAttack` produces:

```
Target: user 'admin' (simulated local login)
Wordlist: D:\Github\password-generator\wordlist.txt
----------------------------------------

=========================================
  PASSWORD FOUND: sunshine
=========================================
Attempts made : 40
Time          : 4 ms
```

The attack stopped after 40 tries — the moment it reached `sunshine` in the
list. A more common password (higher up the file) would need even fewer.

### Example 2 — password not found

Here the target still uses `secret = "sunshine"`, but we point the attack at a
small wordlist that does **not** contain it
(`java DictionaryAttack nomatch.txt`, where the file holds only `123456`,
`password`, `qwerty`, `admin`, `letmein`):

```
Target: user 'admin' (simulated local login)
Wordlist: D:\Github\password-generator\nomatch.txt
----------------------------------------

Password NOT found in the wordlist.
Attempts made : 5
Time          : 1 ms
```

Every entry was tried (all 5) and none matched, so the attack reports failure.
This is exactly what happens when a password is not in the attacker's wordlist —
the whole reason unpredictable passwords are safe against this technique.

---

## 6. Experiments to try

1. **Position matters.** Move the secret higher or lower in `wordlist.txt` and
   watch the "Attempts made" number change. The more common (higher) the
   password, the fewer attempts it takes.
2. **Force a failure.** Set `secret` to something _not_ in the list (e.g.
   `Tr0ub4dor&3xkcd!`). The attack now tries all 120 entries and fails —
   demonstrating why unpredictable passwords win.
3. **Grow the list.** Add more entries to `wordlist.txt` (for example, passwords
   from a public leaked-password list) and see how many the attack cracks.
4. **Feel the scale.** Change the character set / length idea from section 1 and
   calculate the keyspace — notice how quickly pure brute-force becomes
   impossible while a dictionary stays fast.

---

## 7. How real systems defend against this

The project deliberately shows both sides. To make brute-forcing impractical, a
real system combines:

- **Strong passwords** — long and unpredictable, so they are not in any
  wordlist and the keyspace is enormous.
- **Rate limiting** — slow down or delay repeated login attempts.
- **Account lockout** — temporarily block an account after N failed tries.
- **Multi-factor authentication (MFA)** — a stolen password alone is not enough.
- **Slow password hashing** — use `bcrypt`, `scrypt`, or `Argon2` instead of a
  single fast `SHA-256`. These are intentionally expensive, so each guess costs
  the attacker far more time.

---

## 8. Ethics and legal note

This code exists to teach. Running password-guessing tools against systems you
do not own or lack **written authorization** to test is illegal in most
jurisdictions. Use it only on your own machines, in a lab you control, or within
the scope of an authorized security engagement (e.g. a penetration test or a
CTF).

---

## 9. License

This project is released under the **MIT License** — see the [LICENSE](LICENSE)
file for the full text. In short, you are free to use, copy, modify, and share
it, provided the copyright and license notice are kept. It is a master's-degree
coursework project, shared for educational purposes.

---
icon: globe
---

# Armaxis

### Challenge Description

In the depths of the Frontier, Armaxis powers the enemy’s dominance, dispatching weapons to crush rebellion. Fortified and hidden, it controls vital supply chains. Yet, a flaw whispers of opportunity, a crack to expose its secrets and disrupt their plans. Can you breach Armaxis and turn its power against tyranny?

### Flag

`HTB{l00k0ut_f0r_m4rkd0wn_LF1_1n_w1ld!_f7125778561f21b811f1aa33462db200}`

***

### Analysis

We are given two URLs, one is the website itself, and the other is a mail client logged in as `test@email.htb`. We are also given the source code for the challenge. After reading the source code, I found a vulnerability where the reset password token can be used for any user. When doing a password reset, the code only checks if the email exists, and it does not check if the token belongs to the email provided. This means we can use the email we have, and we could reset the admin's password.

```javascript
router.post("/reset-password/request", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send("Email is required.");

  try {
    const user = await getUserByEmail(email);
    if (!user) return res.status(404).send("User not found.");

    const resetToken = crypto.randomBytes(16).toString("hex");
    const expiresAt = Date.now() + 3600000;

    await createPasswordReset(user.id, resetToken, expiresAt);

    await transporter.sendMail({
      from: "noreply@frontier.com",
      to: email,
      subject: "Password Reset",
      text: `Use this token to reset your password: ${resetToken}`,
    });

    res.send("Password reset token sent to your email.");
  } catch (err) {
    console.error("Error processing reset request:", err);
    res.status(500).send("Error processing reset request.");
  }
});

router.post("/reset-password", async (req, res) => {
  const { token, newPassword, email } = req.body; // Added 'email' parameter
  if (!token || !newPassword || !email)
    return res.status(400).send("Token, email, and new password are required.");

  try {
    const reset = await getPasswordReset(token);
    if (!reset) return res.status(400).send("Invalid or expired token.");

    const user = await getUserByEmail(email);
    if (!user) return res.status(404).send("User not found.");

    await updateUserPassword(user.id, newPassword);
    await deletePasswordReset(token);

    res.send("Password reset successful.");
  } catch (err) {
    console.error("Error resetting password:", err);
    res.status(500).send("Error resetting password.");
  }
});
```

The `/weapons/dispatch` endpoint is only accessible to the admin, further solidifying the approach I mentioned previously.

```javascript
router.get("/weapons/dispatch", authenticate, (req, res) => {
  const { role } = req.user;
  if (role !== "admin") return res.status(403).send("Access denied.");
  res.render("dispatch-weapon.html", {
    title: "Dispatch Weapon",
    user: req.user,
  });
});

router.post("/weapons/dispatch", authenticate, async (req, res) => {
  const { role } = req.user;
  if (role !== "admin") return res.status(403).send("Access denied.");

  const { name, price, note, dispatched_to } = req.body;
  if (!name || !price || !note || !dispatched_to) {
    return res.status(400).send("All fields are required.");
  }

  try {
    const parsedNote = parseMarkdown(note);

    await dispatchWeapon(name, price, parsedNote, dispatched_to);

    res.send("Weapon dispatched successfully.");
  } catch (err) {
    console.error("Error dispatching weapon:", err);
    res.status(500).send("Error dispatching weapon.");
  }
});
```

The POST handler also calls the `parseMarkdown`function, where any images on the markdown will be accessed using the `curl`command. But the command execution is not sanitized, therefore vulnerable to command injection. Then the result of the command execution will be stored as Base64 and rendered on an `img`tag.

```javascript
const MarkdownIt = require('markdown-it');
const { execSync } = require('child_process');

const md = new MarkdownIt({
    html: true,
});

function parseMarkdown(content) {
    if (!content) return '';
    return md.render(
        content.replace(/\!\[.*?\]\((.*?)\)/g, (match, url) => {
            try {
                const fileContent = execSync(`curl -s ${url}`);
                const base64Content = Buffer.from(fileContent).toString('base64');
                return `<img src="data:image/*;base64,${base64Content}" alt="Embedded Image">`;
            } catch (err) {
                console.error(`Error fetching image from URL ${url}:`, err.message);
                return `<p>Error loading image: ${url}</p>`;
            }
        })
    );
}

module.exports = { parseMarkdown };
```

On the `database.js`file, we can see that it inserts a default admin user with a random password. We can use `admin@armaxis.htb` when resetting the admin's password.

```javascript
async function initializeDatabase() {
  try {
    await run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email VARCHAR(255) UNIQUE,
            password VARCHAR(255),
            role VARCHAR(50)
        )`);

    await run(`CREATE TABLE IF NOT EXISTS weapons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(255),
            price REAL,
            note TEXT,
            dispatched_to VARCHAR(255),
            FOREIGN KEY (dispatched_to) REFERENCES users (email)
        )`);

    await run(`CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token VARCHAR(64) NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

    const userCount = await get(`SELECT COUNT(*) as count FROM users`);
    if (userCount.count === 0) {
      const insertUser = db.prepare(
        `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
      );
      const runInsertUser = promisify(insertUser.run.bind(insertUser));

      await runInsertUser(
        "admin@armaxis.htb",
        `${crypto.randomBytes(69).toString("hex")}`,
        "admin",
      );
      insertUser.finalize();
      console.log("Seeded initial users.");
    }
  } catch (error) {
    console.error("Error initializing database:", error);
  }
}
```

From the `Dockerfile`, we can also see that the flag will be stored at `/flag.txt`.

```docker
# Use Node.js base image with Alpine Linux
FROM node:alpine

# Install required dependencies for MailHog and supervisord
RUN apk add --no-cache \
    wget \
    supervisor \
    apache2-utils \
    curl

# Install MailHog binary
WORKDIR /
RUN wget https://github.com/mailhog/MailHog/releases/download/v1.0.1/MailHog_linux_amd64
RUN chmod +x MailHog_linux_amd64

# Prepare email directory and copy app files
RUN mkdir -p /email
COPY email-app /email

WORKDIR /email
RUN npm install

# Generate a random password and create authentication file for MailHog
RUN RANDOM_VALUE=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) \
    && htpasswd -nbBC 10 test "$RANDOM_VALUE" > /mailhog-auth \
    && echo $RANDOM_VALUE > /email/password.txt

# Set working directory for the main app
WORKDIR /app

# Copy challenge files and install dependencies
COPY challenge .
RUN npm install

# Copy supervisord configuration
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose ports for the app and email client
EXPOSE 8080
EXPOSE 1337

COPY flag.txt /flag.txt

# Start supervisord
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
```

### Solution

First off, we need to register a new account using the email we have on the mail client.&#x20;

<figure><img src="../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

After registering, we need go through the reset password mechanism, entering `test@email.htb`as our email.

<figure><img src="../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

After requesting a code, we will receive the code on our mail client.

<figure><img src="../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Now, we need to start over the reset password mechanism but now entering `admin@armaxis.htb`as the email and using the token from when we are trying to reset `test@email.htb`.

<figure><img src="../../.gitbook/assets/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

After logging in, we can dispatch a new weapon and injecting a command using markdown images on the note.

<figure><img src="../../.gitbook/assets/image (38).png" alt="" width="563"><figcaption></figcaption></figure>

Then, the flag will be stored as a Base64 on the image source.

<figure><img src="../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

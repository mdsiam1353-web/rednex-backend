const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "10kb" }));

app.get("/", (req, res) => {
  res.json({
    name: "Rednex API",
    status: "running"
  });
});

function verifyTelegramInitData(initData) {
  const botToken = process.env.BOT_TOKEN;

  if (!botToken || !initData || typeof initData !== "string") {
    return null;
  }

  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");

    if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
      return null;
    }

    params.delete("hash");
    params.delete("signature");

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(botToken)
      .digest();

    const calculatedHash = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    const hashBuffer = Buffer.from(receivedHash, "hex");
    const calculatedBuffer = Buffer.from(calculatedHash, "hex");

    if (
      hashBuffer.length !== calculatedBuffer.length ||
      !crypto.timingSafeEqual(hashBuffer, calculatedBuffer)
    ) {
      return null;
    }

    const authDate = Number(params.get("auth_date"));
    const now = Math.floor(Date.now() / 1000);

    if (
      !Number.isFinite(authDate) ||
      authDate > now + 30 ||
      now - authDate > 3600
    ) {
      return null;
    }

    const userText = params.get("user");
    if (!userText) return null;

    const user = JSON.parse(userText);

    if (!user || !Number.isSafeInteger(user.id) || user.id <= 0) {
      return null;
    }

    return {
      id: user.id,
      first_name: user.first_name || "",
      username: user.username || ""
    };
  } catch {
    return null;
  }
}

app.post("/api/auth/telegram", (req, res) => {
  const user = verifyTelegramInitData(req.body?.initData);

  if (!user) {
    return res.status(401).json({
      ok: false,
      error: "Telegram verification failed"
    });
  }

  res.json({
    ok: true,
    user
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Rednex API running on port ${PORT}`);
});

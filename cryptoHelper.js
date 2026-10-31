    const crypto = require("crypto");

    const raw = process.env.ENCRYPTION_KEY.trim();
    const MASTER = Buffer.from(raw, "base64");

    const ENC_KEY = Buffer.from(crypto.hkdfSync("sha256", MASTER, Buffer.alloc(0), "envhub-enc", 32));
    const IDX_KEY = Buffer.from(crypto.hkdfSync("sha256", MASTER, Buffer.alloc(0), "envhub-idx", 32));

    function encrypt(plain) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
    const ct = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return ["v1", iv.toString("base64"), tag.toString("base64"), ct.toString("base64")].join(":");
    }

    function decrypt(payload) {
    try {
        const [v, iv, tag, ct] = String(payload).split(":");
        if (v !== "v1") return null;
        const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, Buffer.from(iv, "base64"));
        decipher.setAuthTag(Buffer.from(tag, "base64"));
        return Buffer.concat([decipher.update(Buffer.from(ct, "base64")), decipher.final()]).toString("utf8");
    } catch {
        return null;
    }
    }


    function blindIndex(value) {
    return crypto.createHmac("sha256", IDX_KEY).update(String(value)).digest("hex");
    }


    function generateApiKey() {
    return `ehk_${crypto.randomBytes(24).toString("hex")}`;
    }


    function generateProjectId() {
    return `prj_${crypto.randomBytes(8).toString("hex")}`;
    }

    module.exports = {
    encrypt,
    decrypt,
    blindIndex,
    generateApiKey,
    generateProjectId
    };

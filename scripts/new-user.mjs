// Usage: node scripts/new-user.mjs <username> "<Display name>" <slug1,slug2|*> [expires YYYY-MM-DD]
// Prints a generated password and the SQL to insert the user into D1.
import { webcrypto as crypto } from "node:crypto";
const [username, displayName = "", slugs = "", expires = ""] = process.argv.slice(2);
if (!username) { console.error("username required"); process.exit(1); }
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const words = "amber,navy,river,delta,orbit,cedar,lumen,pixel,vector,signal,harbor,summit,quartz,meadow,falcon,ember".split(",");
const rnd = (n) => crypto.getRandomValues(new Uint32Array(1))[0] % n;
const password = `${words[rnd(words.length)]}-${words[rnd(words.length)]}-${1000 + rnd(9000)}-${words[rnd(words.length)]}`;
const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: Buffer.from(salt, "hex"), iterations: 100000 }, key, 256);
const allowed = JSON.stringify(slugs ? slugs.split(",").map((s) => s.trim()).filter(Boolean) : []);
const q = (s) => `'${String(s).replace(/'/g, "''")}'`;
console.log(`USERNAME: ${username.toLowerCase()}\nPASSWORD: ${password}\n`);
console.log(`INSERT INTO users (username, password_hash, salt, display_name, allowed_paths, expires_at) VALUES (${q(username.toLowerCase())}, ${q(hex(bits))}, ${q(salt)}, ${q(displayName)}, ${q(allowed)}, ${expires ? q(expires) : "NULL"});`);

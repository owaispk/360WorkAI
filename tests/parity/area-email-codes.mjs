// Contract test for the other uses of the emailed six-digit code (Better Auth emailOTP): sign in with a code, check a code, reset a password with a
// code, and the change-email routes the reference switches off. Runs unchanged against the reference and the rewrite:
//   node area-email-codes.mjs                                                  # reference: web :3005, api :8790
//   W=http://localhost:5290 A=http://localhost:5190 node area-email-codes.mjs  # rewrite (Development, email provider "dev")
// It needs the code that was "emailed": from the rewrite's dev outbox (GET /dev/outbox), from the reference's database (MySQL, `verification` table;
// override with DEN_DB="mysql -uroot -ppassword -h127.0.0.1 openwork_den" if yours differs).
import { execSync } from "node:child_process";
import { W, A, PW, suite, email, call } from "./lib.mjs";

const NEW_PW = "N3w!Passw0rd#2027y";
const DB = process.env.DEN_DB ?? "mysql -uroot -ppassword -h127.0.0.1 openwork_den";
let outbox = null;
async function code(type, to) {
  if (outbox === null) outbox = (await fetch(`${A}/dev/outbox?to=nobody`)).status === 200;
  if (outbox) {
    // The rewrite mails every type with the same template; the newest message to the address holds the newest code.
    const mails = await (await fetch(`${A}/dev/outbox?to=${encodeURIComponent(to)}`)).json();
    return mails.at(-1)?.subject.match(/(\d{6})$/)?.[1] ?? "";
  }
  try { return execSync(`${DB} -N -e "select value from verification where identifier='${type}-otp-${to}' order by created_at desc limit 1"`, { stdio: ["ignore", "pipe", "ignore"] }).toString().trim().split(":")[0]; } catch { return ""; }
}
const post = (path, body, headers) => call(W, path, { method: "POST", body, headers });
const send = (to, type) => post("/api/auth/email-otp/send-verification-otp", { email: to, type });
async function person(name) {
  const e = email("code");
  const su = await post("/api/auth/sign-up/email", { name, email: e, password: PW });
  return { email: e, token: su.json?.token, id: su.json?.user?.id, cookie: su.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ") };
}
const wrong = (c) => (c === "000000" ? "111111" : "000000");

const s = suite("email-codes");

// ---------- sending ----------
await s.t("send-verification-otp for sign-in answers {success:true} for a real and an unknown address alike", async () => {
  const p = await person("Sender"); const a = await send(p.email, "sign-in"); const b = await send(email("ghost"), "sign-in");
  return (a.status === 200 && a.text === '{"success":true}' && b.status === 200 && b.text === a.text) || `${a.status} ${a.text} / ${b.status} ${b.text}`;
});
await s.t("send-verification-otp for forget-password answers the same for a real and an unknown address", async () => {
  const p = await person("Forgetful"); const a = await send(p.email, "forget-password"); const b = await send(email("ghost"), "forget-password");
  return (a.status === 200 && a.text === '{"success":true}' && b.text === a.text) || `${a.status} ${a.text} / ${b.status} ${b.text}`;
});
await s.t("send-verification-otp for change-email: 400 'Invalid OTP type' (switched off)", async () => {
  const r = await send(email("x"), "change-email"); return (r.status === 400 && r.json?.message === "Invalid OTP type") || `${r.status} ${r.text}`;
});
await s.t("the change-email routes answer 400 'Change email with OTP is disabled'", async () => {
  const p = await person("Changer");   // the routes want a signed-in caller
  for (const path of ["/api/auth/email-otp/request-email-change", "/api/auth/email-otp/change-email"]) {
    const r = await post(path, { newEmail: email("n"), otp: "123456" }, { cookie: p.cookie });
    if (r.status !== 400 || r.json?.message !== "Change email with OTP is disabled") return `${path} ${r.status} ${r.text}`;
  }
  return true;
});

// ---------- sign in with a code ----------
const signer = await person("Code Signer");
await send(signer.email, "sign-in");
const signCode = await code("sign-in", signer.email);
await s.t("a sign-in code was issued (six digits)", async () => /^\d{6}$/.test(signCode) || `got "${signCode}"`);
await s.t("check-verification-otp: a wrong code -> 400 INVALID_OTP, the right code -> {success:true} and does not use the code up", async () => {
  const a = await post("/api/auth/email-otp/check-verification-otp", { email: signer.email, type: "sign-in", otp: wrong(signCode) });
  const b = await post("/api/auth/email-otp/check-verification-otp", { email: signer.email, type: "sign-in", otp: signCode });
  const c = await post("/api/auth/email-otp/check-verification-otp", { email: signer.email, type: "sign-in", otp: signCode });
  return (a.status === 400 && a.json?.code === "INVALID_OTP" && b.status === 200 && b.text === '{"success":true}' && c.status === 200) || `${a.status} ${a.text} / ${b.status} ${b.text} / ${c.status}`;
});
await s.t("a code issued for one purpose does not work for another (sign-in code checked as forget-password)", async () => {
  const r = await post("/api/auth/email-otp/check-verification-otp", { email: signer.email, type: "forget-password", otp: signCode }); return (r.status === 400 && r.json?.code === "INVALID_OTP") || `${r.status} ${r.text}`;
});
await s.t("check-verification-otp validates its body (type, email)", async () => {
  const a = await post("/api/auth/email-otp/check-verification-otp", { email: signer.email, type: "nope", otp: "123456" });
  const b = await post("/api/auth/email-otp/check-verification-otp", { email: "nope", type: "sign-in", otp: "123456" });
  return (a.status === 400 && a.json?.code === "VALIDATION_ERROR" && b.status === 400 && b.json?.code === "INVALID_EMAIL") || `${a.status} ${a.text} / ${b.status} ${b.text}`;
});
let session;
await s.t("sign-in/email-otp: a wrong code -> 400 INVALID_OTP and no session", async () => {
  const r = await post("/api/auth/sign-in/email-otp", { email: signer.email, otp: wrong(signCode) }); return (r.status === 400 && r.json?.code === "INVALID_OTP" && !r.headers.getSetCookie().length) || `${r.status} ${r.text}`;
});
await s.t("sign-in/email-otp: the right code signs the person in ({token, user}), verifies the account and sets the session cookie", async () => {
  const r = await post("/api/auth/sign-in/email-otp", { email: signer.email, otp: signCode }); session = r.json?.token;
  const me = await call(A, "/v1/me", { headers: { authorization: `Bearer ${session}` } });
  return (r.status === 200 && !!session && r.json.user?.email === signer.email && r.json.user?.emailVerified === true && r.headers.getSetCookie().some((c) => /session_token=/.test(c)) && me.status === 200) || `${r.status} ${r.text.slice(0, 200)} / me ${me.status}`;
});
await s.t("a sign-in code works once (replay -> 400 INVALID_OTP)", async () => {
  const r = await post("/api/auth/sign-in/email-otp", { email: signer.email, otp: signCode }); return (r.status === 400 && r.json?.code === "INVALID_OTP") || `${r.status} ${r.text}`;
});
await s.t("sign-in/email-otp for an address with no account opens one (verified), as the reference does", async () => {
  const ghost = email("newbie"); await send(ghost, "sign-in"); const c = await code("sign-in", ghost);
  const r = await post("/api/auth/sign-in/email-otp", { email: ghost, otp: c }); return (r.status === 200 && r.json?.user?.email === ghost && r.json.user.emailVerified === true) || `${r.status} ${r.text.slice(0, 200)}`;
});
await s.t("sign-in/email-otp: validation (an invalid email is simply an invalid code, a missing otp is a validation error)", async () => {
  const a = await post("/api/auth/sign-in/email-otp", { email: "nope", otp: "123456" }); const b = await post("/api/auth/sign-in/email-otp", { email: signer.email });
  return (a.status === 400 && a.json?.code === "INVALID_OTP" && b.status === 400 && b.json?.code === "VALIDATION_ERROR") || `${a.status} ${a.text} / ${b.status} ${b.text}`;
});
await s.t("five wrong guesses use the code up: the sixth is 403 TOO_MANY_ATTEMPTS and the right code no longer works", async () => {
  const p = await person("Guesser"); await send(p.email, "sign-in"); const c = await code("sign-in", p.email);
  const results = [];
  for (let i = 0; i < 6; i++) { const r = await post("/api/auth/sign-in/email-otp", { email: p.email, otp: wrong(c) }); results.push(`${r.status}:${r.json?.code}`); }
  const after = await post("/api/auth/sign-in/email-otp", { email: p.email, otp: c });
  return (results.join() === "400:INVALID_OTP,400:INVALID_OTP,400:INVALID_OTP,400:INVALID_OTP,400:INVALID_OTP,403:TOO_MANY_ATTEMPTS" && after.status === 400) || `${results.join()} then ${after.status} ${after.text}`;
});
await s.t("asking for a new code replaces the old one (only the newest works)", async () => {
  const p = await person("Twice"); await send(p.email, "sign-in"); const first = await code("sign-in", p.email);
  await send(p.email, "sign-in"); const second = await code("sign-in", p.email);
  if (first === second) return "the two codes are identical (retry)";
  const old = await post("/api/auth/sign-in/email-otp", { email: p.email, otp: first }); const fresh = await post("/api/auth/sign-in/email-otp", { email: p.email, otp: second });
  return (old.status === 400 && fresh.status === 200) || `${old.status} / ${fresh.status}`;
});

// ---------- reset a password with a code ----------
const forgetful = await person("Forgetful Two");
await send(forgetful.email, "forget-password");
const resetCode = await code("forget-password", forgetful.email);
await s.t("reset-password: a wrong code -> 400 INVALID_OTP", async () => {
  const r = await post("/api/auth/email-otp/reset-password", { email: forgetful.email, otp: wrong(resetCode), password: NEW_PW }); return (r.status === 400 && r.json?.code === "INVALID_OTP") || `${r.status} ${r.text}`;
});
await s.t("reset-password: a password that breaks the rules is 400 and does not use the code up", async () => {
  const r = await post("/api/auth/email-otp/reset-password", { email: forgetful.email, otp: resetCode, password: "abc" }); return r.status === 400 || `${r.status} ${r.text}`;
});
await s.t("reset-password: the right code sets the password, signs every device out and the old password stops working", async () => {
  const r = await post("/api/auth/email-otp/reset-password", { email: forgetful.email, otp: resetCode, password: NEW_PW });
  const old = await post("/api/auth/sign-in/email", { email: forgetful.email, password: PW }); const fresh = await post("/api/auth/sign-in/email", { email: forgetful.email, password: NEW_PW });
  const oldSession = await call(A, "/v1/me", { headers: { authorization: `Bearer ${forgetful.token}` } });
  return (r.status === 200 && r.text === '{"success":true}' && old.status === 401 && fresh.status === 200 && oldSession.status === 401) || `${r.status} ${r.text} / old ${old.status} / new ${fresh.status} / old session ${oldSession.status}`;
});
await s.t("reset-password: the code works once", async () => {
  const r = await post("/api/auth/email-otp/reset-password", { email: forgetful.email, otp: resetCode, password: NEW_PW }); return (r.status === 400 && r.json?.code === "INVALID_OTP") || `${r.status} ${r.text}`;
});
await s.t("reset-password: a sign-in code cannot reset a password", async () => {
  const p = await person("Crossover"); await send(p.email, "sign-in"); const c = await code("sign-in", p.email);
  const r = await post("/api/auth/email-otp/reset-password", { email: p.email, otp: c, password: NEW_PW }); const still = await post("/api/auth/sign-in/email", { email: p.email, password: PW });
  return (r.status === 400 && r.json?.code === "INVALID_OTP" && still.status === 200) || `${r.status} ${r.text} / old password ${still.status}`;
});
s.done();

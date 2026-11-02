// Contract test for password strength scoring at sign-up (zxcvbn, minimum score 3 of 4). Runs unchanged against the reference and the rewrite:
//   node area-password-strength.mjs                                                  # reference
//   W=http://localhost:5081 A=http://localhost:5080 node area-password-strength.mjs  # rewrite
// Breach screening (Have I Been Pwned) needs outside network and is covered by the rewrite's own tests, not here.
import { suite, call, W, email } from "./lib.mjs";
const s = suite("password-strength");
const signUp = (password, name = "Strength Probe", e = email("strength")) => call(W, "/api/auth/sign-up/email", { method: "POST", body: { name, email: e, password } });

await s.t("common passwords that satisfy the basic rules are refused as too weak, with advice", async () => {
  for (const pw of ["Password1!", "Qwerty123!", "Welcome2026!", "Abcdefg1!"]) {
    const r = await signUp(pw);
    if (!(r.status === 400 && r.json?.error === "password_too_weak" && typeof r.json?.message === "string" && r.json.message.length > 0
      && Array.isArray(r.json?.feedback?.suggestions) && "warning" in (r.json?.feedback ?? {}))) return `${pw} -> ${r.status} ${r.text.slice(0, 200)}`;
    const expected = r.json.feedback.warning?.trim() || r.json.feedback.suggestions.find((x) => x.trim())?.trim() || "Password is too weak.";
    if (r.json.message !== expected) return `${pw}: message is not the advice: ${r.json.message} vs ${expected}`;
  }
  return true;
});
await s.t("the basic rules are reported before strength (too short, no digit)", async () => {
  const a = await signUp("Ab1!"); const b = await signUp("Abcdefghij!");
  return (a.json?.error === "password_too_short" && b.json?.error === "password_missing_digit") || `${a.text} / ${b.text}`;
});
await s.t("a long unguessable password signs up", async () => { const r = await signUp("vK9#mQ2$xL7&nR4@tZ8"); return (r.status === 200 && !!r.json?.token) || `${r.status} ${r.text.slice(0, 160)}`; });
await s.t("a weak password creates no account", async () => {
  const e = email("noacct"); await signUp("Password1!", "No Account", e);
  const again = await signUp("vK9#mQ2$xL7&nR4@tZ8", "No Account", e);   // would be 422 USER_ALREADY_EXISTS had the weak attempt created it
  return again.status === 200 || `${again.status} ${again.text.slice(0, 160)}`;
});
s.done();

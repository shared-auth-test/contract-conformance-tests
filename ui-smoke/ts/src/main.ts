const base = "http://127.0.0.1:8120";
const root = document.querySelector<HTMLElement>("#app");
if (!root) throw new Error("missing app root");

root.innerHTML = `
  <h1>Shared Auth smoke</h1>
  <label>Email <input id="email" type="email" required></label>
  <label>Password <input id="password" type="password" minlength="12" required></label>
  <button type="button" id="signup">Sign up</button>
  <button type="button" id="login">Log in</button>
  <pre id="result"></pre>
`;

const email = document.querySelector<HTMLInputElement>("#email")!;
const password = document.querySelector<HTMLInputElement>("#password")!;
const result = document.querySelector<HTMLPreElement>("#result")!;

async function submit(path: "/auth/register" | "/auth/login") {
  result.textContent = "working…";
  try {
    const response = await fetch(base + path, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ email: email.value, password: password.value }),
    });
    result.textContent = String(response.status) + " " + await response.text();
  } catch (error) {
    result.textContent = String(error);
  }
}
document.querySelector("#signup")!.addEventListener("click", () => void submit("/auth/register"));
document.querySelector("#login")!.addEventListener("click", () => void submit("/auth/login"));

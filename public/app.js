const form = document.querySelector("#auth-form");
const emailInput = document.querySelector("#email");
const passwordInput = document.querySelector("#password");
const message = document.querySelector("#form-error");
const submitButton = document.querySelector("#submit-button");
const loginTab = document.querySelector("#login-tab");
const registerTab = document.querySelector("#register-tab");
const title = document.querySelector("#form-title");
const subtitle = document.querySelector("#form-subtitle");
const authContent = document.querySelector("#auth-content");
const signedIn = document.querySelector("#signed-in");
const userEmail = document.querySelector("#user-email");
let mode = "login";

function setMode(nextMode) {
  mode = nextMode;
  const registering = mode === "register";
  loginTab.classList.toggle("active", !registering);
  registerTab.classList.toggle("active", registering);
  loginTab.setAttribute("aria-selected", String(!registering));
  registerTab.setAttribute("aria-selected", String(registering));
  title.textContent = registering ? "Create your account" : "Welcome back";
  subtitle.textContent = registering ? "Use your email and a strong passphrase." : "Enter your details to access your workspace.";
  submitButton.innerHTML = registering ? 'Create account <span aria-hidden="true">→</span>' : 'Sign in <span aria-hidden="true">→</span>';
  passwordInput.autocomplete = registering ? "new-password" : "current-password";
  message.textContent = "";
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...options.headers },
  });
  if (response.status === 204) return null;
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "Request failed.");
  return body;
}

async function loadSession() {
  try {
    const result = await request("/api/auth/me", { method: "GET", headers: {} });
    if (result.user) showSignedIn(result.user);
  } catch {
    message.textContent = "Could not check your session. Refresh to try again.";
  }
}

function showSignedIn(user) {
  userEmail.textContent = user.email;
  authContent.hidden = true;
  signedIn.hidden = false;
}

loginTab.addEventListener("click", () => setMode("login"));
registerTab.addEventListener("click", () => setMode("register"));

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  message.textContent = "";
  if (!form.reportValidity()) return;
  submitButton.disabled = true;
  submitButton.textContent = mode === "register" ? "Creating account…" : "Signing in…";
  try {
    const result = await request(`/api/auth/${mode}`, {
      method: "POST",
      body: JSON.stringify({ email: emailInput.value, password: passwordInput.value }),
    });
    passwordInput.value = "";
    showSignedIn(result.user);
  } catch (error) {
    message.textContent = error.message;
  } finally {
    submitButton.disabled = false;
    setMode(mode);
  }
});

document.querySelector("#logout-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await request("/api/auth/logout", { method: "POST", body: "{}" });
    signedIn.hidden = true;
    authContent.hidden = false;
    passwordInput.value = "";
    setMode("login");
  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

loadSession();

/**
 * Bundled chat UI. Framework-free, shadow-DOM isolated, dark-mode first.
 * Kept intentionally small: the honeypot must look like a plausible internal
 * assistant without shipping a UI framework.
 */

export interface ChatUIOptions {
  theme: "dark" | "light" | "auto";
  persona: string;
  placeholder?: string;
  onSubmit: (text: string) => void;
}

export interface ChatUIController {
  addMessage(role: "user" | "assistant" | "system", content: string): HTMLElement;
  setThinking(value: boolean): void;
  focus(): void;
  destroy(): void;
}

const STYLES = `
:host {
  --tt-bg: #0b0f14;
  --tt-panel: #11161d;
  --tt-border: #1e2630;
  --tt-text: #e6edf3;
  --tt-muted: #8b98a5;
  --tt-accent: #4ade80;
  --tt-accent2: #22d3ee;
  --tt-user: #1d2b3a;
  --tt-radius: 12px;
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  color: var(--tt-text);
  display: block;
  contain: content;
}
:host(.tt-light) {
  --tt-bg: #f6f8fa;
  --tt-panel: #ffffff;
  --tt-border: #d9dee4;
  --tt-text: #10161c;
  --tt-muted: #5b6670;
  --tt-user: #dbeafe;
}
.tt-wrap {
  display: flex; flex-direction: column; height: 100%;
  min-height: 420px; background: var(--tt-panel);
  border: 1px solid var(--tt-border); border-radius: var(--tt-radius);
  overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,.35);
}
.tt-header {
  display: flex; align-items: center; gap: 10px;
  padding: 14px 16px; border-bottom: 1px solid var(--tt-border);
  background: linear-gradient(90deg, rgba(74,222,128,.08), rgba(34,211,238,.08));
}
.tt-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--tt-accent); box-shadow: 0 0 8px var(--tt-accent); }
.tt-title { font-size: 14px; font-weight: 600; letter-spacing: .02em; }
.tt-sub { font-size: 11px; color: var(--tt-muted); margin-left: auto; }
.tt-log { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 10px; scroll-behavior: smooth; }
.tt-msg { max-width: 86%; padding: 10px 13px; border-radius: var(--tt-radius); font-size: 13.5px; line-height: 1.55; white-space: pre-wrap; word-break: break-word; }
.tt-msg.user { align-self: flex-end; background: var(--tt-user); border: 1px solid var(--tt-border); }
.tt-msg.assistant { align-self: flex-start; background: var(--tt-bg); border: 1px solid var(--tt-border); }
.tt-msg.system { align-self: center; background: transparent; color: var(--tt-muted); font-size: 12px; border: none; }
.tt-thinking { align-self: flex-start; display: none; gap: 5px; padding: 10px 13px; }
.tt-thinking.on { display: flex; }
.tt-thinking span { width: 7px; height: 7px; border-radius: 50%; background: var(--tt-muted); animation: tt-blink 1.2s infinite; }
.tt-thinking span:nth-child(2) { animation-delay: .2s; }
.tt-thinking span:nth-child(3) { animation-delay: .4s; }
@keyframes tt-blink { 0%,80%,100%{opacity:.25} 40%{opacity:1} }
.tt-inputrow { display: flex; gap: 8px; padding: 12px; border-top: 1px solid var(--tt-border); background: var(--tt-bg); }
.tt-input {
  flex: 1; resize: none; background: var(--tt-panel); color: var(--tt-text);
  border: 1px solid var(--tt-border); border-radius: 10px;
  padding: 10px 12px; font-size: 13.5px; outline: none; min-height: 42px; max-height: 140px;
  font-family: inherit;
}
.tt-input:focus { border-color: var(--tt-accent2); }
.tt-send {
  border: none; cursor: pointer; border-radius: 10px; padding: 0 18px;
  font-size: 13.5px; font-weight: 600; color: #06130a;
  background: linear-gradient(135deg, var(--tt-accent), var(--tt-accent2));
}
.tt-send:hover { filter: brightness(1.08); }
`;

export function mountChatUI(container: HTMLElement, options: ChatUIOptions): ChatUIController {
  const host = document.createElement("div");
  host.style.setProperty("height", "100%");
  if (options.theme === "light") host.className = "tt-light";
  const shadow = host.attachShadow({ mode: "open" });

  const style = document.createElement("style");
  style.textContent = STYLES;

  const wrap = document.createElement("div");
  wrap.className = "tt-wrap";

  const header = document.createElement("div");
  header.className = "tt-header";
  const dot = document.createElement("div");
  dot.className = "tt-dot";
  const title = document.createElement("div");
  title.className = "tt-title";
  title.textContent = options.persona;
  const sub = document.createElement("div");
  sub.className = "tt-sub";
  sub.textContent = "online";
  header.append(dot, title, sub);

  const log = document.createElement("div");
  log.className = "tt-log";

  const thinking = document.createElement("div");
  thinking.className = "tt-thinking";
  const b1 = document.createElement("span");
  const b2 = document.createElement("span");
  const b3 = document.createElement("span");
  thinking.append(b1, b2, b3);

  const inputRow = document.createElement("div");
  inputRow.className = "tt-inputrow";
  const input = document.createElement("textarea");
  input.className = "tt-input";
  input.rows = 1;
  input.placeholder = options.placeholder ?? "Message the assistant...";
  const send = document.createElement("button");
  send.className = "tt-send";
  send.type = "submit";
  send.textContent = "Send";

  const form = document.createElement("form");
  form.appendChild(inputRow);
  inputRow.append(input, send);

  function submit() {
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    options.onSubmit(text);
  }
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    submit();
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  });

  wrap.append(header, log, thinking, form);
  shadow.append(style, wrap);
  container.replaceChildren(host);

  return {
    addMessage(role, content) {
      const el = document.createElement("div");
      el.className = `tt-msg ${role}`;
      el.textContent = content;
      log.appendChild(el);
      log.scrollTop = log.scrollHeight;
      return el;
    },
    setThinking(value) {
      thinking.classList.toggle("on", value);
      log.scrollTop = log.scrollHeight;
    },
    focus() {
      input.focus();
    },
    destroy() {
      host.remove();
    },
  };
}

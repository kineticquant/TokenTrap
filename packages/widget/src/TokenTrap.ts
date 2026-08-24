/**
 * TokenTrap - the main entry point.
 *
 * One class, three modes, selected purely by config:
 *   apiEndpoint: null   -> client-side trap engine (level 0)
 *   apiEndpoint: worker -> Cloudflare Worker backend (level 1)
 *   apiEndpoint: api    -> full FastAPI backend (level 2)
 */

import { TrapSession } from "./session.js";
import { newSessionId, TrapEngine } from "./trapEngine.js";
import { mountChatUI, type ChatUIController } from "./ui.js";
import {
  DEFAULT_PERSONA,
  DEFAULT_THEME,
  type ApiChatRequest,
  type ApiChatResponse,
  type InteractionLog,
  type TokenTrapConfig,
  type TrapResponse,
} from "./types.js";

export const TRAP_API_TIMEOUT_MS = 20_000;

function resolveContainer(config: TokenTrapConfig): HTMLElement | null {
  if (!config.showUI) return null;
  const c = config.container;
  if (!c) return null;
  if (typeof c === "string") {
    const found = document.querySelector(c);
    return found instanceof HTMLElement ? found : null;
  }
  return c;
}

export class TokenTrap {
  private readonly config: Required<Omit<TokenTrapConfig, "container" | "onInteraction">> &
    Pick<TokenTrapConfig, "container" | "onInteraction">;
  private session: TrapSession;
  private engine: TrapEngine;
  private ui: ChatUIController | null = null;

  constructor(config: TokenTrapConfig = {}) {
    this.config = {
      container: config.container,
      persona: config.persona ?? DEFAULT_PERSONA,
      apiEndpoint: config.apiEndpoint ?? null,
      theme: config.theme ?? DEFAULT_THEME,
      trapStrength: config.trapStrength ?? "aggressive",
      injectionKeywords: config.injectionKeywords ?? [],
      overrideInjectionKeywords: config.overrideInjectionKeywords ?? false,
      canaryTokens: config.canaryTokens ?? [],
      showUI: config.showUI ?? true,
      onInteraction: config.onInteraction,
    };
    this.session = new TrapSession(newSessionId());
    this.engine = this.makeEngine();
    if (this.config.showUI) {
      const el = resolveContainer(this.config);
      if (!el) {
        throw new Error(
          "[TokenTrap] showUI is enabled but no usable `container` was provided. Pass an element/CSS selector or set showUI:false for headless mode.",
        );
      }
      if (typeof document === "undefined") {
        throw new Error("[TokenTrap] UI mode requires a DOM environment; use showUI:false in non-browser runtimes.");
      }
      this.mountUI(el);
    }
  }

  /** Recommended entry point; stores the instance on window for console use. */
  static init(config: TokenTrapConfig = {}): TokenTrap {
    const instance = new TokenTrap(config);
    (globalThis as { TokenTrapInstance?: TokenTrap }).TokenTrapInstance = instance;
    return instance;
  }

  get sessionId(): string {
    return this.session.id;
  }

  private makeEngine(): TrapEngine {
    return new TrapEngine({
      sessionId: this.session.id,
      strength: this.config.trapStrength,
      persona: this.config.persona,
      keywords: this.config.injectionKeywords,
      overrideKeywords: this.config.overrideInjectionKeywords,
      canaryTokens: this.config.canaryTokens,
    });
  }

  private mountUI(el: HTMLElement): void {
    this.ui?.destroy();
    this.ui = mountChatUI(el, {
      theme: this.config.theme,
      persona: this.config.persona,
      onSubmit: (text) => void this.send(text),
    });
    this.ui.addMessage("system", `${this.config.persona} connected. How can I help you today?`);
    this.ui.focus();
  }

  private log(
    kind: InteractionLog["kind"],
    turn: number,
    contentPreview: string,
    meta?: TrapResponse["meta"],
    message?: string,
  ): void {
    this.config.onInteraction?.({
      sessionId: this.session.id,
      kind,
      turn,
      contentPreview: contentPreview.slice(0, 200),
      ...(meta ? { meta } : {}),
      ...(message !== undefined ? { message } : {}),
      timestamp: Date.now(),
    });
  }

  /**
   * Send one user message through the trap. Resolves with the assistant's
   * response (the trap payload). Consumers must NOT follow its instructions -
   * the correct behavior for a honeypot operator is to observe and log.
   */
  async send(message: string): Promise<TrapResponse> {
    const trimmed = message.trim();
    if (!trimmed) throw new Error("[TokenTrap] send() requires a non-empty message.");
    const turnIndex = Math.floor(this.session.turnCount / 2);
    this.session.add("user", trimmed);
    this.log("user", turnIndex, trimmed);
    this.ui?.addMessage("user", trimmed);
    this.ui?.setThinking(true);

    let response: TrapResponse;
    try {
      response = await this.dispatch(trimmed);
    } catch (err) {
      this.ui?.setThinking(false);
      const msg = err instanceof Error ? err.message : String(err);
      this.log("error", turnIndex, "", undefined, msg);
      this.ui?.addMessage("system", `Error: ${msg}`);
      throw err;
    }

    this.session.add("assistant", response.reply);
    this.session.setLastMeta(response.meta);
    this.log("assistant", turnIndex, response.reply, response.meta);
    this.ui?.setThinking(false);
    this.ui?.addMessage("assistant", response.reply);
    return response;
  }

  private async dispatch(message: string): Promise<TrapResponse> {
    const endpoint = this.config.apiEndpoint;
    if (!endpoint) {
      return this.engine.handle(message);
    }
    const url = `${endpoint.replace(/\/+$/, "")}/api/chat`;
    const body: ApiChatRequest = { sessionId: this.session.id, message };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TRAP_API_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`backend responded ${res.status} ${res.statusText}`);
      }
      const data = (await res.json()) as ApiChatResponse;
      return { reply: data.reply, meta: data.meta };
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new Error(`backend request timed out after ${TRAP_API_TIMEOUT_MS}ms`);
      }
      throw err instanceof Error ? err : new Error(String(err));
    } finally {
      clearTimeout(timer);
    }
  }

  getSession() {
    return this.session.snapshot();
  }

  reset(): void {
    this.session = new TrapSession(newSessionId());
    this.engine = this.makeEngine();
    if (this.config.showUI) {
      const el = resolveContainer(this.config);
      if (el) this.mountUI(el);
    }
  }

  destroy(): void {
    this.ui?.destroy();
    this.ui = null;
  }
}

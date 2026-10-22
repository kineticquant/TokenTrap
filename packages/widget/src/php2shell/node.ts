import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import type { Php2ShellContext, Php2ShellDecoy } from "./types.js";

function nodeHeaders(req: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) headers.set(key, value.join(", "));
    else if (value !== undefined) headers.set(key, value);
  }
  return headers;
}

function nodeIp(req: IncomingMessage): string {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff) return xff.split(",")[0]!.trim();
  return req.socket.remoteAddress ?? "unknown";
}

async function handleNodeRequest(
  decoy: Php2ShellDecoy,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const host = req.headers.host ?? "localhost";
  const url = new URL(req.url ?? "/", `http://${host}`);
  const method = req.method ?? "GET";
  const init: RequestInit & { duplex?: "half" } = {
    method,
    headers: nodeHeaders(req),
    duplex: method === "GET" || method === "HEAD" ? undefined : "half",
  };
  if (method !== "GET" && method !== "HEAD") {
    init.body = Readable.toWeb(req) as unknown as ReadableStream;
  }
  const request = new Request(url, init);
  const context: Php2ShellContext = { clientIp: nodeIp(req) };
  const response = await decoy.handle(request, context);
  if (!response) return false;

  res.statusCode = response.status;
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") return;
    res.setHeader(key, value);
  });
  const getSetCookie = (
    response.headers as Headers & { getSetCookie?: () => string[] }
  ).getSetCookie;
  const setCookies = typeof getSetCookie === "function" ? getSetCookie.call(response.headers) : [];
  if (setCookies.length > 0) res.setHeader("set-cookie", setCookies);

  const body = method === "HEAD" ? Buffer.alloc(0) : Buffer.from(await response.arrayBuffer());
  res.end(body);
  return true;
}

export function toNodeHandler(decoy: Php2ShellDecoy) {
  return async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const handled = await handleNodeRequest(decoy, req, res);
    if (!handled) {
      res.statusCode = 404;
      res.end("Not Found");
    }
  };
}

export function toExpressMiddleware(decoy: Php2ShellDecoy) {
  return function middleware(
    req: IncomingMessage,
    res: ServerResponse,
    next: (err?: unknown) => void,
  ): void {
    handleNodeRequest(decoy, req, res)
      .then((handled) => {
        if (!handled) next();
      })
      .catch(next);
  };
}

export function toNextHandlers(decoy: Php2ShellDecoy) {
  const handler = (request: Request): Promise<Response> =>
    decoy.handle(request).then((response) => response ?? new Response("Not Found", { status: 404 }));
  return {
    GET: handler,
    POST: handler,
    HEAD: handler,
    PUT: handler,
    PATCH: handler,
    DELETE: handler,
    OPTIONS: handler,
  };
}

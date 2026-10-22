import { createServer } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { createPhp2ShellDecoy } from "../src/php2shell";
import { toNodeHandler } from "../src/php2shell/node";

const servers: Array<{ close: () => Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

async function start(decoy = createPhp2ShellDecoy({ now: () => 1000 })): Promise<string> {
  const server = createServer(toNodeHandler(decoy));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no address");
  servers.push({ close: () => new Promise((resolve) => server.close(() => resolve())) });
  return `http://127.0.0.1:${address.port}`;
}

describe("Node adapter", () => {
  it("serves a decoy page over a real HTTP server", async () => {
    const base = await start();
    const res = await fetch(`${base}/`, { headers: { "user-agent": "curl/8" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("x-powered-by")).toBe("PHP/8.3.14");
    expect(res.headers.get("set-cookie")).toContain("PHPSESSID=");
  });

  it("returns a PHP fatal for a multipart pressure request", async () => {
    const base = await start();
    const boundary = "----trap";
    const body = [
      `--${boundary}`,
      'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"',
      "",
      "x",
      `--${boundary}--`,
      "",
    ].join("\r\n");
    const res = await fetch(`${base}/index.php`, {
      method: "POST",
      headers: {
        "content-type": `multipart/form-data; boundary=${boundary}`,
        "user-agent": "python-requests/2.32",
      },
      body,
    });
    expect(res.status).toBe(500);
    expect(await res.text()).toContain("PHP Fatal error");
  });
});

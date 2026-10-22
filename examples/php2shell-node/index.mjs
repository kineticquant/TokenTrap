import { createServer } from "node:http";
import { createPhp2ShellDecoy } from "tokentrap-ai/php2shell";
import { toNodeHandler } from "tokentrap-ai/php2shell/node";

const decoy = createPhp2ShellDecoy({
  profile: "generic",
  trapStrength: "aggressive",
  onEvent: (event) => console.log(JSON.stringify(event)),
});

createServer(toNodeHandler(decoy)).listen(8080, "127.0.0.1", () => {
  console.log("PHP2Shell decoy on http://127.0.0.1:8080");
  console.log("Defensive decoy - deploy only on a host you are authorized to monitor.");
});

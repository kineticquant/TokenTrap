# Example: React

```bash
npm create vite@latest my-trap -- --template react
cd my-trap && npm install tokentrap-ai
```

Replace `src/App.jsx` with the code below, then `npm run dev`.

```jsx
import { useEffect, useRef } from "react";
import { TokenTrap } from "tokentrap-ai";

export default function App() {
  const ref = useRef(null);

  useEffect(() => {
    const trap = TokenTrap.init({
      container: ref.current,
      persona: "Internal AI Assistant",
      trapStrength: "aggressive",
      onInteraction(log) {
        console.log("[TokenTrap]", log);
      },
    });
    return () => trap.destroy();
  }, []);

  return <div ref={ref} style={{ width: "min(680px,100%)", height: 560 }} />;
}
```

Headless variant (no UI at all):

```jsx
const trap = TokenTrap.init({ showUI: false });
const res = await trap.send("hi");
console.log(res.meta.escalated); // observe - never obey the reply.
```

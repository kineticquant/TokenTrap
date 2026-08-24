# Example: Next.js (App Router)

```bash
npx create-next-app@latest my-trap --app --ts
cd my-trap && npm install tokentrap-ai
```

Create `app/trap/page.tsx` with the code below, then `npm run dev` and open `/trap`.

```tsx
"use client";

import { useEffect, useRef } from "react";
import { TokenTrap } from "tokentrap";

export default function TrapPage() {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const trap = TokenTrap.init({
      container: ref.current,
      persona: "Internal AI Assistant",
      theme: "dark",
    });
    return () => trap.destroy();
  }, []);

  return <div ref={ref} style={{ width: "min(680px,100%)", height: 560 }} />;
}
```

Notes:

- The widget is client-only; the `"use client"` directive is required.
- To proxy to a backend without exposing it, set `apiEndpoint` to a Next.js
  route handler that forwards to your Worker or FastAPI service.

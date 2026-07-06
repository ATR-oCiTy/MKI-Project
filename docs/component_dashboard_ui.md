# Component Documentation: Dashboard UI

The **Dashboard UI** is a React + TypeScript application built with Vite. It serves as the visual command center for the Autonomous SOC Range, offering real-time insight into network traffic, ML inference, the LangGraph pipeline, and - since the most recent redesign - a working surface for the human-in-the-loop approval flow that previously had no UI at all.

## Architectural Design

The application is built within `App.tsx`, `ErrorBoundary.tsx`, and styled via `index.css`. It does not rely on heavy component libraries; instead it uses custom CSS Grid layouts and raw CSS variables for a dark "cyber" aesthetic.

### 1. Theming & Glassmorphism (`index.css`)
- **Dark Mode Palette**: Deep slate/navy backgrounds (`#020617`, `#0f172a`), accented by Neon Cyan (`#06b6d4`), Cyber Purple (`#8b5cf6`), and Alert Crimson (`#ef4444`).
- **Glassmorphism**: Panels use `background: rgba(30, 41, 59, 0.6); backdrop-filter: blur(16px);` for a translucent, frosted-glass effect.

### 2. Navigation - six purpose-built views
The dashboard was reorganized from a 3-tab layout (Overview / AI Reports / Debug Logs) into six views, specifically to give the approval flow and the containment lifecycle their own dedicated surfaces rather than being crammed into one "Overview":

- **Command Center** (`dashboard` tab) - the landing view. A metrics strip (Network Status, Pending Review, Active Blocks, Mean Time to Containment - the last one computed live by matching each `SUCCESS` mitigation's timestamp back to the alert that caused it, not a placeholder), the LangGraph pipeline tracker (four nodes, hover for the full markdown report), Live Threat Intelligence, a Network Anomaly area chart, and a "Guardrail Activity" panel showing counts of Contained / Pending review / Denied / Refused (allow-list) / Rate limited flows as horizontal bars, so the safety systems are visible instead of buried in logs.
- **Triage Queue** (`triage` tab) - the human-in-the-loop surface. A live badge on the nav item shows the pending count. Each card shows the source/destination pair, target criticality, attack type and confidence, the triage report, and how long it's been waiting, with **Contain** and **Dismiss** buttons wired to `/api/approve` and `/api/deny`.
- **Mitigations** (`mitigations` tab) - a manual block form (any IP, subject to the same allow-list/rate-limit as the automated path via `/api/trigger`), a live table of active blocks with a real countdown to TTL expiry and an Unblock button (`/api/unblock`), and a full mitigation history table with status badges.
- **AI Reports** (`reports` tab) - an archive of every Triage/Context report generated, newest first, rendered as markdown cards. Unchanged from the original design.
- **Simulation Control** (`simulation` tab) - the attacker panel (source IP config, randomize/real-tools checkboxes, per-attack Start/Stop, Global Reset), deliberately moved out of the main command view into its own page - a real SOC operator's dashboard wouldn't have a "launch attack" panel front and center, since that's a testing capability specific to this cyber range.
- **Debug Logs** (`logs` tab) - a filterable tail of `system.log` plus the attacker node's own log. Unchanged from the original design.

### 3. Resilience: `ErrorBoundary.tsx`
Each tab's content is wrapped in a React error boundary, keyed by the active tab so switching tabs remounts it fresh. This exists because of a real production bug: some Gemini response shapes return `.content` as a list of blocks rather than a plain string, which - before a backend fix coerced it at the source - crashed React's render with no recovery and blanked the entire app. The boundary is a backstop: if anything ever throws again, only that view shows a "this view hit an error, try again" fallback instead of the whole app going blank.

## Data Synchronization

The UI is stateless with respect to the backend. A single polling effect fetches `/api/alerts`, `/api/mitigations`, `/api/flow`, `/api/pending_approvals`, and `/api/active_blocks` via `Promise.all()` every 1,500ms; the Debug Logs tab additionally fetches `/api/logs` and `/api/attacker_logs` while active.
- **Dynamic Log Clearing**: "Clear Logs" sends an API request that physically scrubs the backend `.log` files, rather than just clearing local React state (which would immediately refill on the next poll).
- **Action feedback**: Approve/Deny/Block/Unblock actions show an inline confirmation toast populated directly from the API response message, not a generic "success" string.

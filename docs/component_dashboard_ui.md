# Component Documentation: Dashboard UI

The **Dashboard UI** is a React + TypeScript application built with Vite. It serves as the visual command center for the Autonomous SOC Range, offering real-time insights into the network traffic, machine learning inference, and LangGraph agent execution.

## Architectural Design

The application is built entirely within `App.tsx` and styled via `index.css`. It does not rely on heavy component libraries (like Material UI or Tailwind); instead, it utilizes custom CSS Grid layouts and raw CSS variables to achieve a highly specific "Cyber Aesthetic."

### 1. Theming & Glassmorphism (`index.css`)
- **Dark Mode Palette**: Utilizes deep slate/navy backgrounds (`#020617`, `#0f172a`), accented by vibrant Neon Cyan (`#06b6d4`), Cyber Purple (`#8b5cf6`), and Alert Crimson (`#ef4444`).
- **Glassmorphism**: Panels are styled with `background: rgba(30, 41, 59, 0.6); backdrop-filter: blur(16px);`. This creates a translucent, frosted-glass effect that adds significant depth to the layout.

### 2. Layout Structure (`App.tsx`)
The dashboard recently transitioned from a top-tab layout to a **Sidebar Navigation** paradigm.
- **Left Sidebar**: Houses branding, navigation links, and a pulsating global `System Status` indicator.
- **Main View (CSS Grid)**:
  - **KPI Metrics**: A top row of cards displaying live computations (e.g., Active Mitigations, Average AI Confidence).
  - **AI Pipeline Node**: A horizontal workflow tracker mapping the `Detection -> Triage -> Context -> Response` stages of the LangGraph swarm.
  - **Network Anomaly Chart**: An `AreaChart` (via `recharts`) plotting byte volumes over time, styled with a custom cyan gradient fill to match the neon theme.
  - **Threat Intelligence Tables**: Displays the raw flow metadata (IPs, Ports, Attack Type) exactly as categorized by the ML models.
  - **Attacker Control Panel**: A fully interactive terminal allowing the user to configure custom/spoofed Source IPs, and independently `START` and `STOP` specific attack vectors.

## Data Synchronization

The UI is entirely stateless in regards to the backend. It relies on a rigorous polling mechanism to ensure the display perfectly mirrors the live state of the SOC.
- **`setInterval` Polling**: An effect hook triggers `Promise.all()` every 1,500ms, concurrently fetching `/api/alerts`, `/api/mitigations`, `/api/flow`, and the log streams.
- **Dynamic Log Clearing**: The Debug Console features a robust "Clear Logs" feature. Instead of just clearing the React state (which would immediately refill on the next poll), it sends an API request that physically scrubs the backend `.log` files on the host OS, instantly wiping the specific category from the UI.

import { useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { getToken, setToken } from "./api/client";
import { AlertQueue } from "./pages/AlertQueue";
import { Hosts } from "./pages/Hosts";
import { Hunt } from "./pages/Hunt";
import { IncidentDetail } from "./pages/IncidentDetail";

export default function App() {
  const [token, setTokenState] = useState(getToken());

  const onTokenChange = (value: string) => {
    setTokenState(value);
    setToken(value);
  };

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">EDR Console</span>
        <nav>
          <NavLink to="/" end>
            Alerts
          </NavLink>
          <NavLink to="/hosts">Hosts</NavLink>
          <NavLink to="/hunt">Hunt</NavLink>
        </nav>
        <input
          className="token-input"
          type="password"
          placeholder="API token"
          value={token}
          onChange={(e) => onTokenChange(e.target.value)}
          title="EDR_API_TOKEN from the backend .env, kept in localStorage"
        />
      </header>
      <main>
        <Routes>
          <Route path="/" element={<AlertQueue />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/hosts" element={<Hosts />} />
          <Route path="/hunt" element={<Hunt />} />
        </Routes>
      </main>
    </div>
  );
}

import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

// StrictMode is intentionally not used: in development it runs effects twice,
// which would send every DNS check twice and double-count history.
ReactDOM.createRoot(document.getElementById("root")!).render(<App />);

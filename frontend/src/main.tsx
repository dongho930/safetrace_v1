import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// 폰트는 번들에 포함한다(외부 폰트 서버를 쓰지 않음: CSP·격리 운영)
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "@fontsource/ibm-plex-sans-kr/400.css";
import "@fontsource/ibm-plex-sans-kr/500.css";
import "@fontsource/ibm-plex-sans-kr/600.css";
import "@fontsource/ibm-plex-sans-kr/700.css";
import App from "./App";
import "./style.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

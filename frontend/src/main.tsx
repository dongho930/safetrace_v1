import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// 폰트는 번들에 포함한다(외부 폰트 서버를 쓰지 않음: CSP·격리 운영). 가변 글꼴을 글자 범위로 나눈 120조각, 화면에 필요한 조각만 받는다
import "pretendard-gov/dist/web/variable/pretendardvariable-gov-dynamic-subset.css";
import App from "./App";
import "./style.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

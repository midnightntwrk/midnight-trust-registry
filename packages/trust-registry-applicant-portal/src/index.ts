import { createApplicantPortalApp } from "./app.js";

const root = document.querySelector<HTMLElement>("#app");

if (root === null) {
  throw new Error("expected #app root element");
}

createApplicantPortalApp(root);

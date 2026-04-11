import { render, screen } from "@testing-library/react";
import App from "./App";

test("renders login form for unauthenticated users", () => {
  localStorage.clear();
  window.history.pushState({}, "", "/login");

  render(<App />);

  expect(screen.getByRole("heading", { name: /secure sign in/i })).toBeInTheDocument();
});

// router.js - Hash routes

const routes = new Map();
let notFoundHandler = null;

export function route(path, handler) {
  routes.set(path, handler);
}

export function setNotFound(handler) {
  notFoundHandler = handler;
}

export function navigate(path) {
  window.location.hash = path;
}

function currentPath() {
  const hash = window.location.hash.slice(1);
  return hash || "/";
}

export function resolve() {
  const path = currentPath();
  // Try exact match first
  if (routes.has(path)) return routes.get(path)();
  // Try prefix match (for /processes/123 etc.)
  for (const [route, handler] of routes) {
    if (path.startsWith(route + "/")) return handler();
  }
  if (notFoundHandler) notFoundHandler();
}

export function startRouter() {
  window.addEventListener("hashchange", resolve);
  resolve();
}

// jsdom does not implement ResizeObserver. Radix uses it to position overlays,
// so tests provide the inert observer that a layout-less DOM requires.
if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

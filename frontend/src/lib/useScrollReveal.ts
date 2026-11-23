import { useEffect } from "react";

const SELECTOR = [
  ".ui-card",
  ".reference-card",
  "[data-reveal]",
  "main header",
  ".reference-landing section > div",
  ".auth-light section > *",
].join(",");

/**
 * Fades and softly elevates cards and sections as they enter the viewport.
 * Automatically respects prefers-reduced-motion.
 */
export function useScrollReveal() {
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const seen = new WeakSet<Element>();
    const io = new IntersectionObserver(
      (entries) => {
        let index = 0;
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          const el = entry.target as HTMLElement;
          el.style.transitionDelay = `${Math.min(index++ * 60, 300)}ms`;
          el.classList.add("reveal-in");
          io.unobserve(el);

          // Clean up classes after animation finishes so normal hover states apply cleanly
          window.setTimeout(() => {
            el.style.transitionDelay = "";
            el.classList.remove("reveal", "reveal-in");
          }, 1000);
        }
      },
      { threshold: 0.08, rootMargin: "0px 0px -4% 0px" }
    );

    const scan = () => {
      document.querySelectorAll(SELECTOR).forEach((el) => {
        if (seen.has(el) || el.closest("[role='dialog']")) return;
        seen.add(el);
        el.classList.add("reveal");
        io.observe(el);
      });
    };

    scan();

    let frame = 0;
    const mo = new MutationObserver(() => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(scan);
    });

    mo.observe(document.body, { childList: true, subtree: true });

    return () => {
      io.disconnect();
      mo.disconnect();
      cancelAnimationFrame(frame);
    };
  }, []);
}

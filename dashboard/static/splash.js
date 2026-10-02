// Vigilon post-login splash.
// login.html sets sessionStorage "vigilon_splash" = "1" after a successful sign-in.
// dashboard.html sees that flag, hides the page, and this script plays the splash once.
(function () {
  const root = document.documentElement;
  if (!root.classList.contains("splash-pending")) return;

  // Remove the flag straight away, so a page refresh doesn't replay the splash
  try { sessionStorage.removeItem("vigilon_splash"); } catch (e) { /* storage blocked: ignore */ }

  // ---- Owl shapes, in the pixel coordinates of the original vigilon.png ----
  const OWL = {
    body: "M248,102 L389,180 L529,102 L611,322 C616,338 612,350 604,364 C560,440 470,550 389,663 C308,550 218,440 174,364 C166,350 162,338 167,322 Z",
    head: "M248,102 L389,180 L529,102 L611,322 L613,340 L165,340 L167,322 Z",
    chest: "M230,341 C300,368 370,430 382,532 Q389,548 396,532 C408,430 478,368 548,341 Z",
    wingL: "M230,342 C300,368 370,430 382,532 C330,500 262,430 230,342 Z",
    wingR: "M548,342 C478,368 408,430 396,532 C448,500 516,430 548,342 Z",
    seam: "M389,505 C384,560 378,610 383,655",
    beak: "M360,356 L418,356 L389,406 Z",
    eyes: [[301, 283], [477, 283]],
    r: 49,
    anchors: [[248, 102], [389, 180], [529, 102], [611, 322], [604, 364], [389, 663], [174, 364], [167, 322]],
    handles: [[[604, 364], [560, 440]], [[389, 663], [470, 550]], [[389, 663], [308, 550]], [[174, 364], [218, 440]]],
  };

  // Real loading steps. Each one fills a quarter of the ring.
  // run() resolves to nothing when all is well, or to a short warning text.
  const STEPS = [
    {
      label: "Verifying session",
      run: () => authFetch("/api/auth/me").then((r) => { if (!r.ok) throw new Error(); }),
    },
    {
      label: "Connecting to agents",
      run: () => authFetch("/api/agents/status").then((r) => r.json()).then((data) => {
        const agents = data.agents || [];
        const stopped = agents.filter((a) => a.status !== "Running").length;
        if (stopped) return `${stopped}/${agents.length} agents stopped`;
      }),
    },
    {
      label: "Loading threat data",
      run: () => authFetch("/api/threats/recent?page=1&page_size=1").then((r) => { if (!r.ok) throw new Error(); }),
    },
    {
      label: "Preparing dashboard",
      // "load" fires when the page and all its images/styles have finished loading
      run: () => (document.readyState === "complete"
        ? null
        : new Promise((resolve) => window.addEventListener("load", () => resolve(), { once: true }))),
    },
  ];
  const STEP_MIN_MS = 450;   // a step never flashes by faster than this
  const STEP_MAX_MS = 5000;  // a step that takes longer is marked amber, and the splash moves on

  const EASE = "cubic-bezier(.4,0,.2,1)";
  const A = (el, keyframes, opt) => el.animate(keyframes, Object.assign({ fill: "forwards", easing: EASE }, opt));
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  // ---- Build the splash ----
  function owlFill() {
    return `
      <path d="${OWL.body}" fill="#3E3289"/>
      <path d="${OWL.head}" fill="#4B3F94"/>
      <path d="${OWL.chest}" fill="#4B3F94"/>
      <path d="${OWL.wingL}" fill="#574BA1"/><path d="${OWL.wingR}" fill="#574BA1"/>
      <path d="${OWL.seam}" fill="none" stroke="#31276D" stroke-width="3" stroke-linecap="round"/>
      <path class="sp-sil" d="${OWL.body}" fill="none" stroke="#31276D" stroke-width="4" stroke-linejoin="round"/>
      ${OWL.eyes.map(([x, y]) => `<circle class="sp-eye" cx="${x}" cy="${y}" r="${OWL.r}" fill="#fff" stroke="#31276D" stroke-width="4"/>`).join("")}
      <path d="${OWL.beak}" fill="#fff" stroke="#31276D" stroke-width="4" stroke-linejoin="round"/>`;
  }

  function owlSVG() {
    const tr = (d) => `<path pathLength="1" d="${d}"/>`;
    const anchors =
      OWL.handles.map(([[x1, y1], [x2, y2]]) =>
        `<g><line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/><circle cx="${x2}" cy="${y2}" r="6"/></g>`).join("") +
      OWL.anchors.map(([x, y]) => `<rect x="${x - 8}" y="${y - 8}" width="16" height="16"/>`).join("");
    return `<svg viewBox="150 90 480 590" aria-hidden="true">
      <defs><radialGradient id="sp-dotg"><stop offset="0" stop-color="#fff"/><stop offset=".35" stop-color="#A99BFF"/><stop offset="1" stop-color="#A99BFF" stop-opacity="0"/></radialGradient></defs>
      <g class="sp-fill">${owlFill()}</g>
      <g class="sp-trace">
        ${tr(OWL.body)}${tr(OWL.wingL)}${tr(OWL.wingR)}${tr(OWL.seam)}
        ${OWL.eyes.map(([x, y]) => `<circle class="sp-t-eye" pathLength="1" cx="${x}" cy="${y}" r="${OWL.r}"/>`).join("")}
        ${tr(OWL.beak)}
      </g>
      <g class="sp-anchors">${anchors}</g>
      <circle class="sp-dot" r="26" fill="url(#sp-dotg)" cx="248" cy="102"/>
    </svg>`;
  }

  function ringSVG() {
    const R = 88;
    const pt = (deg) => [100 + R * Math.cos(deg * Math.PI / 180), 100 + R * Math.sin(deg * Math.PI / 180)];
    let arcs = "";
    for (let i = 0; i < 4; i++) {
      const a0 = -90 + i * 90 + 6, a1 = a0 + 78;  // 4 arcs of 78°, with 12° gaps
      const [x0, y0] = pt(a0), [x1, y1] = pt(a1);
      const d = `M${x0.toFixed(2)},${y0.toFixed(2)} A${R},${R} 0 0 1 ${x1.toFixed(2)},${y1.toFixed(2)}`;
      arcs += `<path class="track" d="${d}"/><path class="seg" pathLength="1" d="${d}"/>`;
    }
    return `<svg class="sp-ring" viewBox="0 0 200 200" aria-hidden="true">
      <circle class="ticks" cx="100" cy="100" r="97"/><circle class="inner" cx="100" cy="100" r="78"/>${arcs}</svg>`;
  }

  const splash = document.createElement("div");
  splash.id = "vg-splash";
  splash.setAttribute("role", "status");
  splash.setAttribute("aria-label", "Loading Vigilon");
  splash.innerHTML = `
    <div class="sp-bg"></div><div class="sp-grid"></div>
    <div class="sp-emblem">
      <div class="sp-owl"><div class="sp-glow"></div>${owlSVG()}</div>
      ${ringSVG()}
    </div>
    <div class="sp-words"><div class="sp-wordmark">Vigilon</div><div class="sp-tag">XDR Platform</div></div>
    <div class="sp-status"><span class="sp-step">${STEPS[0].label}…</span><span class="sp-count">1/${STEPS.length}</span></div>`;
  document.body.prepend(splash);

  const q = (sel) => splash.querySelector(sel);
  const qa = (sel) => [...splash.querySelectorAll(sel)];
  const owlWrap = q(".sp-owl"), fill = q(".sp-fill"), trace = q(".sp-trace"), anchors = q(".sp-anchors");
  const dot = q(".sp-dot"), glow = q(".sp-glow"), grid = q(".sp-grid"), bg = q(".sp-bg");
  const words = q(".sp-words"), status = q(".sp-status"), stepText = q(".sp-step"), stepCount = q(".sp-count");
  const ring = q(".sp-ring"), segs = qa(".sp-ring .seg"), eyes = qa(".sp-eye"), sil = q(".sp-sil");

  // ---- Phase 1: trace the owl like a blueprint, then fill it in ----
  async function traceOwl() {
    A(status, [{ opacity: 0 }, { opacity: 1 }], { duration: 400 });
    A(grid, [{ opacity: 0 }, { opacity: 1 }], { duration: 500 });
    const paths = [...trace.children];
    const timing = [[1000, 0], [600, 380], [600, 380], [400, 600], [500, 300], [500, 300], [350, 650]];
    paths.forEach((el, i) => A(el, [{ strokeDashoffset: 1.05 }, { strokeDashoffset: 0 }],
      { duration: timing[i][0], delay: timing[i][1], easing: "cubic-bezier(.5,0,.3,1)" }));
    [...anchors.children].forEach((el, i) => A(el, [{ opacity: 0 }, { opacity: 1 }], { duration: 200, delay: 80 + i * 70 }));
    runDot(1000);
    await wait(1150);

    A(fill, [{ opacity: 0 }, { opacity: 1 }], { duration: 450 });
    A(glow, [{ opacity: 0 }, { opacity: 1 }], { duration: 700 });
    A(trace, [{ opacity: 1 }, { opacity: 0 }], { duration: 450, delay: 200 });
    A(anchors, [{ opacity: 1 }, { opacity: 0 }], { duration: 300 });
    A(grid, [{ opacity: 1 }, { opacity: 0.35 }], { duration: 600 });
    A(words, [{ opacity: 0, transform: "translateY(6px)" }, { opacity: 1, transform: "none" }],
      { duration: 500, delay: 150 });
  }

  // A glowing dot that travels along the owl's outline while it is traced
  function runDot(duration) {
    const len = sil.getTotalLength(), t0 = performance.now();
    const tick = (now) => {
      const t = Math.min(1, (now - t0) / duration), e = 1 - Math.pow(1 - t, 2);
      const p = sil.getPointAtLength(len * e);
      dot.setAttribute("cx", p.x);
      dot.setAttribute("cy", p.y);
      dot.style.opacity = t < 0.9 ? 1 : (1 - t) * 10;
      if (t < 1) requestAnimationFrame(tick); else dot.style.opacity = 0;
    };
    requestAnimationFrame(tick);
  }

  // ---- Phase 2: one ring segment per real loading step ----
  function withTimeout(promise, ms) {
    return Promise.race([promise, wait(ms).then(() => { throw new Error("timeout"); })]);
  }

  async function loadSteps(startedEarly) {
    for (let i = 0; i < STEPS.length; i++) {
      stepText.classList.remove("warn");
      stepText.textContent = STEPS[i].label + "…";
      stepCount.textContent = `${i + 1}/${STEPS.length}`;

      let warning = null;
      try {
        const [result] = await Promise.all([withTimeout(startedEarly[i], STEP_MAX_MS), wait(STEP_MIN_MS)]);
        if (result) warning = result;
      } catch (e) {
        warning = e.message === "timeout" ? `${STEPS[i].label}: slow to respond` : `${STEPS[i].label} failed`;
      }
      if (warning) {
        segs[i].classList.add("warn");
        stepText.classList.add("warn");
        stepText.textContent = warning;
      }
      A(segs[i], [{ strokeDashoffset: 1.05 }, { strokeDashoffset: 0 }], { duration: 380 });
      if (warning) await wait(900); // give the user time to read the warning
    }
    const warned = segs.filter((s) => s.classList.contains("warn")).length;
    stepText.textContent = warned ? `Ready · ${warned} warning${warned > 1 ? "s" : ""}` : "Ready";
    await wait(200);
  }

  // ---- Phase 3: the owl blinks once ----
  async function blink() {
    eyes.forEach((e) => e.animate(
      [{ transform: "scaleY(1)" }, { transform: "scaleY(.08)", offset: 0.45 }, { transform: "scaleY(1)" }],
      { duration: 300, easing: "ease-in-out" }));
    await wait(550);
  }

  // ---- Phase 4: reveal the dashboard; the owl flies into the header logo ----
  async function reveal() {
    root.classList.remove("splash-pending"); // dashboard becomes visible under the splash

    const logo = document.querySelector(".header-brand-img");
    if (!logo) {
      A(splash, [{ opacity: 1 }, { opacity: 0 }], { duration: 300 });
      await wait(320);
    } else {
      segs.forEach((s) => { if (!s.classList.contains("warn")) s.classList.add("ok"); });
      const from = owlWrap.getBoundingClientRect(), to = logo.getBoundingClientRect();
      const dx = (to.left + to.width / 2) - (from.left + from.width / 2);
      const dy = (to.top + to.height / 2) - (from.top + from.height / 2);
      // Same viewBox as images/vigilon-owl.svg, so landing at the logo's full height lines up exactly
      const s = to.height / from.height;
      logo.style.opacity = "0"; // the flying owl stands in for the logo until it lands
      A(owlWrap, [{ transform: "none" }, { transform: `translate(${dx}px, ${dy}px) scale(${s})` }],
        { duration: 800, delay: 250, easing: "cubic-bezier(.65,0,.25,1)" });
      A(glow, [{ opacity: 1 }, { opacity: 0 }], { duration: 400, delay: 250 });
      A(ring, [{ transform: "scale(1)", opacity: 1 }, { transform: "scale(1.6)", opacity: 0 }], { duration: 650 });
      A(words, [{ opacity: 1 }, { opacity: 0 }], { duration: 220 });
      A(status, [{ opacity: 1 }, { opacity: 0 }], { duration: 220 });
      A(grid, [{ opacity: 0.35 }, { opacity: 0 }], { duration: 400 });
      A(bg, [{ opacity: 1 }, { opacity: 0 }], { duration: 600, delay: 300 });
      await wait(1060);
      logo.style.opacity = "";
      A(owlWrap, [{ opacity: 1 }, { opacity: 0 }], { duration: 150 });
      await wait(160);
    }
    splash.remove();
  }

  // ---- Run ----
  async function play() {
    // Start all loading requests now, so they run while the owl is being traced
    const startedEarly = STEPS.map((step) => Promise.resolve().then(step.run));
    startedEarly.forEach((p) => p.catch(() => {})); // errors are handled per step in loadSteps
    await traceOwl();
    await loadSteps(startedEarly);
    await blink();
    await reveal();
  }
  play();
})();

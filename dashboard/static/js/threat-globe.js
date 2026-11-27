let threatGlobe = null;

function initThreatGlobe() {
    const container = document.getElementById("globe-container");
    if (!container || threatGlobe) return;

    threatGlobe = Globe()(container)
        .globeImageUrl("https://cdn.jsdelivr.net/npm/three-globe@2.33.0/example/img/earth-blue-marble.jpg")
        .backgroundImageUrl("")
        .backgroundColor("rgba(0, 0, 0, 0)")
        .width(container.clientWidth)
        .height(420)
        .arcColor(d => d.risk_score >= 0.8 ? "rgba(231,76,60,0.8)" : "rgba(124,107,240,0.6)")
        .arcDashLength(0.4)
        .arcDashGap(0.2)
        .arcDashAnimateTime(1500)
        .arcStroke(0.5)
        .pointColor(() => "#7c6bf0")
        .pointAltitude(0.01)
        .pointRadius(0.4);

    window.addEventListener("resize", () => {
        if (threatGlobe && container.clientWidth > 0) {
            threatGlobe.width(container.clientWidth);
        }
    });

    loadThreatOrigins();
}

function loadThreatOrigins() {
    if (!threatGlobe) return;

    authFetch("/api/threat-origins")
        .then(r => r.json())
        .then(data => {
            const origins = data.origins || [];

            const serverLat = 53.35;
            const serverLng = -6.26;

            const points = origins.map(o => ({
                lat: o.lat,
                lng: o.lng,
                label: `${o.ip} (${o.country || "Unknown"})`,
            }));

            const arcs = origins.map(o => ({
                startLat: o.lat,
                startLng: o.lng,
                endLat: serverLat,
                endLng: serverLng,
                risk_score: o.risk_score || 0.5,
            }));

            threatGlobe.pointsData(points);
            threatGlobe.arcsData(arcs);

            threatGlobe.controls().autoRotate = true;
            threatGlobe.controls().autoRotateSpeed = 0.5;

            const legend = document.getElementById("globe-legend");
            if (legend) {
                legend.textContent = origins.length > 0 ? `${origins.length} threat origin${origins.length !== 1 ? "s" : ""} in the last 24h` : "No network threats with geolocatable IPs in the last 24h";
            }
        })
        .catch(() => {});
}
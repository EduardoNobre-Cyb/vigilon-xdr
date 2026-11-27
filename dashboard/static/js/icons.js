// Vigilon XDR - SVG Icon Set

(function () {
  var S = ' viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">';

  window.ICONS = {
    // Sidebar / page titles
    dashboard:  '<svg' + S + '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
    agents:     '<svg' + S + '<circle cx="12" cy="12" r="3"/><circle cx="4.5" cy="4.5" r="2"/><circle cx="19.5" cy="4.5" r="2"/><circle cx="4.5" cy="19.5" r="2"/><circle cx="19.5" cy="19.5" r="2"/><line x1="6.3" y1="6.3" x2="9.8" y2="9.8"/><line x1="14.2" y1="9.8" x2="17.7" y2="6.3"/><line x1="6.3" y1="17.7" x2="9.8" y2="14.2"/><line x1="14.2" y1="14.2" x2="17.7" y2="17.7"/></svg>',
    edr:        '<svg' + S + '<path d="M12 2L4 7v6c0 5.25 3.4 10.15 8 11.25 4.6-1.1 8-6 8-11.25V7l-8-5z"/><path d="M9 12l2 2 4-4"/></svg>',
    database:   '<svg' + S + '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.66 3.58 3 8 3s8-1.34 8-3V6"/><path d="M4 12v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/></svg>',
    logs:       '<svg' + S + '<path d="M14 3v4a1 1 0 001 1h4"/><path d="M5 3h9l5 5v11a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2z"/><path d="M7 13h10M7 17h6"/></svg>',
    team:       '<svg' + S + '<path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>',

    // Dashboard cards
    trendUp:    '<svg' + S + '<polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/></svg>',
    warning:    '<svg' + S + '<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="16.5" r=".5" fill="currentColor"/></svg>',
    bell:       '<svg' + S + '<path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/><line x1="12" y1="2" x2="12" y2="4"/></svg>',
    target:     '<svg' + S + '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
    chain:      '<svg' + S + '<path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>',
    search:     '<svg' + S + '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="8" y1="11" x2="14" y2="11"/><line x1="11" y1="8" x2="11" y2="14"/></svg>',
    analytics:  '<svg' + S + '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="3" y1="20" x2="21" y2="20"/></svg>',
    review:     '<svg' + S + '<path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0H5a2 2 0 01-2-2v-4m6 6h10a2 2 0 002-2v-4"/><circle cx="6" cy="12" r="1" fill="currentColor"/><circle cx="15" cy="8" r="1" fill="currentColor"/><circle cx="15" cy="16" r="1" fill="currentColor"/></svg>',

    // EDR / OS sensors
    windows:    '<svg' + S + '<path d="M3 6.5l7-1.3v6.3H3z"/><path d="M13 4.5l8-1.5v8.5h-8z"/><path d="M3 13.5h7v6.3l-7-1.3z"/><path d="M13 13.5h8v8.5l-8-1.5z"/></svg>',
    linux:      '<svg' + S + '<path d="M12 2C9.5 2 7.5 4.5 7.5 8c0 2.5-1 5.5-1 8 0 2 1.5 3.5 3.5 3.5h4c2 0 3.5-1.5 3.5-3.5 0-2.5-1-5.5-1-8 0-3.5-2-6-5-6z"/><path d="M10 11.5c0-.5.9-1 2-1s2 .5 2 1v5c0 .8-.9 1.5-2 1.5s-2-.7-2-1.5z"/><circle cx="10.3" cy="7" r="0.8" fill="currentColor" stroke="none"/><circle cx="13.7" cy="7" r="0.8" fill="currentColor" stroke="none"/><path d="M11.2 9l.8 1 .8-1"/></svg>',
    bolt:       '<svg' + S + '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
    bellDot:    '<svg' + S + '<path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/><circle cx="18" cy="4" r="3" fill="currentColor" stroke="none"/></svg>',
    sensor:     '<svg' + S + '<rect x="2" y="4" width="20" height="13" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',

    // Actions / controls
    upload:     '<svg' + S + '<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
    edit:       '<svg' + S + '<path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>',
    save:       '<svg' + S + '<path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>',
    key:        '<svg' + S + '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.78 7.78 5.5 5.5 0 017.78-7.78zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
    lock:       '<svg' + S + '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>',
    refresh:    '<svg' + S + '<polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>',
    eye:        '<svg' + S + '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>',
    eyeOff:     '<svg' + S + '<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>',
    quarantine: '<svg' + S + '<path d="M12 2L4 7v6c0 5.25 3.4 10.15 8 11.25 4.6-1.1 8-6 8-11.25V7l-8-5z"/><line x1="8" y1="8" x2="16" y2="16"/><line x1="16" y1="8" x2="8" y2="16"/></svg>',
    radar:      '<svg' + S + '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/><line x1="12" y1="2" x2="12" y2="12"/><path d="M12 12l7.07 7.07"/></svg>',
    globe:      '<svg' + S + '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10A15.3 15.3 0 0112 2z"/></svg>',
  };

  // Auto-fill every <span data-icon="name"> in the page
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-icon]').forEach(function (el) {
      var svg = window.ICONS[el.dataset.icon];
      if (svg) el.innerHTML = svg;
    });
  });
})();
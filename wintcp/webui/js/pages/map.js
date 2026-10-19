import { h, clear } from "../h.js";
import { connectionKey, hostnameLabel } from "../connections.js";
import { button } from "../ui/button.js";
import { card, cardHeader, cardTitle, cardContent, emptyState } from "../ui/card.js";
import { fmtInt } from "../format.js";

const TOPOJSON_URL = "/vendor/world-atlas/countries-110m.json";
const MAPLIBRE_URL = "/vendor/maplibre/maplibre-gl.mjs";
const MAPLIBRE_WORKER_URL = "/vendor/maplibre/maplibre-gl-worker.mjs";
const NAME_TO_ISO2 = {
  "Fiji": "FJ", "Tanzania": "TZ", "W. Sahara": "EH", "Canada": "CA",
  "United States of America": "US", "Kazakhstan": "KZ", "Uzbekistan": "UZ",
  "Papua New Guinea": "PG", "Indonesia": "ID", "Argentina": "AR", "Chile": "CL",
  "Dem. Rep. Congo": "CD", "Somalia": "SO", "Kenya": "KE", "Sudan": "SD",
  "Chad": "TD", "Haiti": "HT", "Dominican Rep.": "DO", "Russia": "RU",
  "Bahamas": "BS", "Falkland Is.": "FK", "Norway": "NO", "Greenland": "GL",
  "Fr. S. Antarctic Lands": "TF", "Timor-Leste": "TL", "South Africa": "ZA",
  "Lesotho": "LS", "Mexico": "MX", "Uruguay": "UY", "Brazil": "BR",
  "Bolivia": "BO", "Peru": "PE", "Colombia": "CO", "Panama": "PA",
  "Costa Rica": "CR", "Nicaragua": "NI", "Honduras": "HN", "El Salvador": "SV",
  "Guatemala": "GT", "Belize": "BZ", "Venezuela": "VE", "Guyana": "GY",
  "Suriname": "SR", "France": "FR", "Ecuador": "EC", "Puerto Rico": "PR",
  "Jamaica": "JM", "Cuba": "CU", "Zimbabwe": "ZW", "Botswana": "BW",
  "Namibia": "NA", "Senegal": "SN", "Mali": "ML", "Mauritania": "MR",
  "Benin": "BJ", "Niger": "NE", "Nigeria": "NG", "Cameroon": "CM",
  "Togo": "TG", "Ghana": "GH", "Côte d'Ivoire": "CI", "CÃ´te d'Ivoire": "CI",
  "Guinea": "GN", "Guinea-Bissau": "GW", "Liberia": "LR", "Sierra Leone": "SL",
  "Burkina Faso": "BF", "Central African Rep.": "CF", "Congo": "CG",
  "Gabon": "GA", "Eq. Guinea": "GQ", "Zambia": "ZM", "Malawi": "MW",
  "Mozambique": "MZ", "eSwatini": "SZ", "Angola": "AO", "Burundi": "BI",
  "Israel": "IL", "Lebanon": "LB", "Madagascar": "MG", "Palestine": "PS",
  "Gambia": "GM", "Tunisia": "TN", "Algeria": "DZ", "Jordan": "JO",
  "United Arab Emirates": "AE", "Qatar": "QA", "Kuwait": "KW", "Iraq": "IQ",
  "Oman": "OM", "Vanuatu": "VU", "Cambodia": "KH", "Thailand": "TH",
  "Laos": "LA", "Myanmar": "MM", "Vietnam": "VN", "North Korea": "KP",
  "South Korea": "KR", "Mongolia": "MN", "India": "IN", "Bangladesh": "BD",
  "Bhutan": "BT", "Nepal": "NP", "Pakistan": "PK", "Afghanistan": "AF",
  "Tajikistan": "TJ", "Kyrgyzstan": "KG", "Turkmenistan": "TM", "Iran": "IR",
  "Syria": "SY", "Armenia": "AM", "Sweden": "SE", "Belarus": "BY",
  "Ukraine": "UA", "Poland": "PL", "Austria": "AT", "Hungary": "HU",
  "Moldova": "MD", "Romania": "RO", "Lithuania": "LT", "Latvia": "LV",
  "Estonia": "EE", "Germany": "DE", "Bulgaria": "BG", "Greece": "GR",
  "Turkey": "TR", "Albania": "AL", "Croatia": "HR", "Switzerland": "CH",
  "Luxembourg": "LU", "Belgium": "BE", "Netherlands": "NL", "Portugal": "PT",
  "Spain": "ES", "Ireland": "IE", "New Caledonia": "NC", "Solomon Is.": "SB",
  "New Zealand": "NZ", "Australia": "AU", "Sri Lanka": "LK", "China": "CN",
  "Taiwan": "TW", "Italy": "IT", "Denmark": "DK", "United Kingdom": "GB",
  "Iceland": "IS", "Azerbaijan": "AZ", "Georgia": "GE", "Philippines": "PH",
  "Malaysia": "MY", "Brunei": "BN", "Slovenia": "SI", "Finland": "FI",
  "Slovakia": "SK", "Czechia": "CZ", "Eritrea": "ER", "Japan": "JP",
  "Paraguay": "PY", "Yemen": "YE", "Saudi Arabia": "SA", "Antarctica": "AQ",
  "N. Cyprus": "CY", "Cyprus": "CY", "Morocco": "MA", "Egypt": "EG",
  "Libya": "LY", "Ethiopia": "ET", "Djibouti": "DJ", "Somaliland": "SO",
  "Uganda": "UG", "Rwanda": "RW", "Bosnia and Herz.": "BA", "Macedonia": "MK",
  "Serbia": "RS", "Montenegro": "ME", "Kosovo": "XK",
  "Trinidad and Tobago": "TT", "S. Sudan": "SS",
};

let mapLibrePromise = null;

export async function renderMap(page, store) {
  clear(page);
  page.append(
    h("div", { class: "page-heading map-heading" },
      h("div", {},
        h("h1", { class: "page-title" }, "Map"),
        h("p", { class: "page-description" }, "Live remote connections by country."),
      ),
      h("div", { class: "map-heading-actions" },
        h("span", { class: "muted text-sm", id: "map-status" }, "Loading map…"),
        button({ id: "map-projection", variant: "outline", "aria-label": "Switch map projection", "aria-pressed": "true" }, "2D map"),
        h("button", {
          class: "btn btn-outline btn-sm", id: "map-retry", type: "button", hidden: true,
          onclick: () => document.dispatchEvent(new Event("wintcp:retry-map")),
        }, "Retry map"),
      ),
    ),
    h("div", { class: "map-layout" },
      h("div", { class: "map-panel" },
        h("div", { id: "map-canvas", class: "map-canvas", role: "application", "aria-label": "Interactive world map" }),
      ),
      h("div", { class: "map-sidebar" },
        card({},
          cardHeader({}, cardTitle({}, "Top Countries")),
          cardContent({}, h("div", { id: "map-countries" })),
        ),
        h("p", { class: "map-accuracy muted text-sm" },
          "Markers show country-level locations. They do not identify an IP address’s exact location."),
      ),
    ),
  );

  let map = null;
  let popup = null;
  let pulseTimer = 0;
  let destroyed = false;
  const requests = new AbortController();
  let countriesGeoJson = null;
  let connectionSource = null;
  let lastDataSignature = "";
  const container = page.querySelector("#map-canvas");
  const status = page.querySelector("#map-status");
  const projectionButton = page.querySelector("#map-projection");
  const retryButton = page.querySelector("#map-retry");

  page._mapDestroy = () => {
    destroyed = true;
    requests.abort();
    if (pulseTimer) window.clearInterval(pulseTimer);
    if (popup) popup.remove();
    if (map) map.remove();
    page._mapUpdate = null;
    page._mapDestroy = null;
  };

  const update = () => {
    if (!map || !countriesGeoJson || destroyed) return;
    const data = mapData(countriesGeoJson, store.get());
    if (data.signature === lastDataSignature) return;
    lastDataSignature = data.signature;
    const countrySource = map.getSource("countries");
    connectionSource = map.getSource("connections");
    if (countrySource) countrySource.setData(data.countries);
    if (connectionSource) connectionSource.setData(data.connections);
    renderCountryList(page.querySelector("#map-countries"), data.topCountries, store.get());
    const accuracy = page.querySelector(".map-accuracy");
    if (accuracy) {
      accuracy.textContent = data.connections.features.length
        ? "Markers show country-level locations. They do not identify an IP address’s exact location."
        : "No geolocated remote connections in the current snapshot.";
    }
  };
  page._mapUpdate = update;
  projectionButton.addEventListener("click", () => {
    if (!map) return;
    const type = map.getProjection()?.type === "globe" ? "mercator" : "globe";
    map.setProjection({ type });
    projectionButton.textContent = type === "globe" ? "2D map" : "Globe view";
    projectionButton.setAttribute("aria-pressed", String(type === "globe"));
  });

  try {
    const topoResponse = await fetch(TOPOJSON_URL, { signal: requests.signal });
    if (!topoResponse.ok) throw new Error(`Country data returned HTTP ${topoResponse.status}`);
    countriesGeoJson = topoToGeoJson(await topoResponse.json());
    if (destroyed) return;
    if (!countriesGeoJson.features.length) throw new Error("Country data contains no map features");
    const maplibre = await loadMapLibre();
    if (destroyed || !container.isConnected) return;
    maplibre.setWorkerUrl(new URL(MAPLIBRE_WORKER_URL, location.origin).toString());
    map = new maplibre.Map({
      container,
      style: {
        version: 8,
        projection: { type: "globe" },
        sources: {},
        layers: [{ id: "background", type: "background", paint: { "background-color": cssColor("--background", "#ffffff") } }],
      },
      center: [0, 18],
      zoom: 1.1,
      minZoom: 0.5,
      maxZoom: 8,
      renderWorldCopies: false,
      attributionControl: true,
      canvasContextAttributes: { antialias: true },
    });
    popup = new maplibre.Popup({ closeButton: false, closeOnClick: false, offset: 10, maxWidth: "300px" });

    map.on("load", () => {
      if (destroyed) return;
      const data = mapData(countriesGeoJson, store.get());
      lastDataSignature = data.signature;
      map.addSource("countries", {
        type: "geojson",
        data: data.countries,
        promoteId: "iso2",
        attribution: "Country boundaries: Natural Earth via world-atlas",
      });
      map.addSource("connections", { type: "geojson", data: data.connections });
      map.addLayer({
        id: "country-fill",
        type: "fill",
        source: "countries",
        paint: {
          "fill-color": ["case", [">", ["get", "count"], 0],
            ["interpolate", ["linear"], ["get", "ratio"], 0, cssColor("--chart-2", "#38bdf8"), 1, cssColor("--chart-1", "#f97316")],
            cssColor("--muted", "#e5e7eb")],
          "fill-opacity": 0.88,
        },
      });
      map.addLayer({
        id: "country-borders",
        type: "line",
        source: "countries",
        paint: { "line-color": cssColor("--border", "#64748b"), "line-width": 0.65, "line-opacity": 0.8 },
      });
      map.addLayer({
        id: "connection-pulse",
        type: "circle",
        source: "connections",
        paint: {
          "circle-radius": 9,
          "circle-color": cssColor("--chart-1", "#f97316"),
          "circle-opacity": 0.24,
          "circle-blur": 0.45,
          "circle-pitch-alignment": "viewport",
        },
      });
      map.addLayer({
        id: "connection-markers",
        type: "circle",
        source: "connections",
        paint: {
          "circle-radius": 4.5,
          "circle-color": cssColor("--chart-1", "#f97316"),
          "circle-stroke-color": cssColor("--background", "#ffffff"),
          "circle-stroke-width": 1.2,
          "circle-pitch-alignment": "viewport",
        },
      });
      installMapInteractions(map, popup);
      renderCountryList(page.querySelector("#map-countries"), data.topCountries, store.get());
      pulseTimer = window.setInterval(() => {
        const phase = Date.now() / 650;
        const pulse = 0.25 + (Math.sin(phase) + 1) * 0.18;
        const radius = 7 + (Math.sin(phase) + 1) * 2.5;
        if (map?.getLayer("connection-pulse")) {
          map.setPaintProperty("connection-pulse", "circle-opacity", pulse);
          map.setPaintProperty("connection-pulse", "circle-radius", radius);
        }
      }, 180);
      status.textContent = "";
      retryButton.hidden = true;
      projectionButton.disabled = false;
    });
    map.on("error", (event) => {
      if (destroyed) return;
      const message = event?.error?.message;
      if (message) status.textContent = `Map error: ${message}`;
    });
    projectionButton.disabled = true;
    update();
  } catch (error) {
    if (destroyed) return;
    status.textContent = `Map unavailable: ${error.message}`;
    retryButton.hidden = false;
    renderCountryList(page.querySelector("#map-countries"), [], store.get());
  }
}

export function updateMap(page, store) {
  if (typeof page._mapUpdate === "function") page._mapUpdate(store);
}

async function loadMapLibre() {
  if (!mapLibrePromise) mapLibrePromise = import(MAPLIBRE_URL);
  return mapLibrePromise;
}

function topoToGeoJson(topo) {
  const [kx, ky] = topo.transform.scale;
  const [tx, ty] = topo.transform.translate;
  const decoded = topo.arcs.map((arc) => {
    let x = 0;
    let y = 0;
    return arc.map(([dx, dy]) => {
      x += dx;
      y += dy;
      return [x * kx + tx, y * ky + ty];
    });
  });
  const arcCoordinates = (ref) => {
    const coords = decoded[ref < 0 ? ~ref : ref] || [];
    return ref < 0 ? coords.slice().reverse() : coords;
  };
  const stitchRing = (refs) => {
    const result = [];
    for (const ref of refs) {
      const arc = arcCoordinates(ref);
      result.push(...(result.length ? arc.slice(1) : arc));
    }
    if (result.length && (result[0][0] !== result[result.length - 1][0] ||
        result[0][1] !== result[result.length - 1][1])) result.push(result[0]);
    return result;
  };
  const geometries = topo.objects.countries.geometries;
  const features = geometries.map((geometry) => {
    const name = geometry.properties?.name || "Unknown country";
    const code = NAME_TO_ISO2[name] || String(geometry.id || "");
    const coordinates = geometry.type === "Polygon"
      ? geometry.arcs.map(stitchRing)
      : geometry.arcs.map((polygon) => polygon.map(stitchRing));
    return {
      type: "Feature",
      id: code,
      properties: { iso2: code, name, count: 0, ratio: 0 },
      geometry: { type: geometry.type, coordinates },
    };
  }).filter((feature) => /^[A-Z]{2}$/.test(feature.id));
  return { type: "FeatureCollection", features };
}

export function mapData(geoJson, state) {
  const connections = Array.isArray(state.connections) ? state.connections : [];
  const counts = new Map();
  const rowsByCountry = new Map();
  for (const row of connections) {
    if (row.removed || !state.geoSummary?.geoIpConfigured) continue;
    const code = String(row.country || "").trim().toUpperCase();
    const remote = String(row.remote || row.remoteAddress || "").trim();
    if (!/^[A-Z]{2}$/.test(code) || !remote || remote === "—" || remote === "*") continue;
    counts.set(code, (counts.get(code) || 0) + 1);
    if (!rowsByCountry.has(code)) rowsByCountry.set(code, []);
    rowsByCountry.get(code).push(row);
  }
  const maxCount = Math.max(1, ...counts.values());
  const features = geoJson.features.map((feature) => {
    const count = counts.get(feature.id) || 0;
    return { ...feature, properties: { ...feature.properties, count, ratio: count / maxCount } };
  });
  const countries = { type: "FeatureCollection", features };
  const connectionFeatures = [];
  for (const [code, rows] of rowsByCountry) {
    const feature = geoJson.features.find((candidate) => candidate.id === code);
    if (!feature) continue;
    const candidates = interiorPoints(feature.geometry);
    rows.forEach((row, index) => {
      const point = candidates[index % candidates.length];
      connectionFeatures.push({
        type: "Feature",
        id: String(row.id ?? `${row.pid || ""}:${row.remote}:${row.rport || ""}:${index}`),
        properties: {
          process: row.process || row.processName || "Unknown process",
          pid: row.pid || "Unknown",
          remote: row.remote || row.remoteAddress || "Unknown",
          port: row.rport || "",
          protocol: row.proto || "",
          state: row.state || "",
          hostname: hostnameLabel(row.hostname),
          connectionKey: `connection:${connectionKey(row)}`,
          country: feature.properties.name,
          locationNote: "Country-level GeoIP estimate",
        },
        geometry: { type: "Point", coordinates: point },
      });
    });
  }
  const points = { type: "FeatureCollection", features: connectionFeatures };
  const topCountries = [...counts].map(([code, count]) => ({
    code,
    count,
    name: geoJson.features.find((feature) => feature.id === code)?.properties.name || code,
  })).sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  return {
    countries,
    connections: points,
    topCountries,
    signature: JSON.stringify([state.geoSummary?.geoIpConfigured, [...counts], connectionFeatures.map((feature) => [feature.id, ...Object.values(feature.properties)])]),
  };
}

function interiorPoints(geometry) {
  const polygons = geometry.type === "Polygon" ? [geometry.coordinates] : geometry.coordinates;
  const mainPolygon = polygons.reduce((best, polygon) => {
    const outer = polygon[0] || [];
    if (!outer.length) return best;
    const longitudes = outer.map((point) => point[0]);
    const latitudes = outer.map((point) => point[1]);
    const width = Math.min(Math.max(...longitudes) - Math.min(...longitudes), 360 - (Math.max(...longitudes) - Math.min(...longitudes)));
    const height = Math.max(...latitudes) - Math.min(...latitudes);
    return width * height > best.area ? { polygon, area: width * height } : best;
  }, { polygon: null, area: -1 }).polygon;
  if (!mainPolygon) return [[0, 0]];
  const outer = mainPolygon[0];
  const longitudes = outer.map((point) => point[0]);
  const latitudes = outer.map((point) => point[1]);
  const minX = Math.min(...longitudes);
  const maxX = Math.max(...longitudes);
  const minY = Math.min(...latitudes);
  const maxY = Math.max(...latitudes);
  const points = [];
  for (let y = 0; y < 14; y++) {
    for (let x = 0; x < 14; x++) {
      const candidate = [minX + ((x + 0.5) / 14) * (maxX - minX), minY + ((y + 0.5) / 14) * (maxY - minY)];
      if (pointInRing(candidate, outer) && !mainPolygon.slice(1).some((ring) => pointInRing(candidate, ring))) points.push(candidate);
    }
  }
  if (points.length) return points;
  const fallback = outer[0];
  return fallback ? [fallback] : [[0, 0]];
}

function pointInRing(point, ring) {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const [xi, yi] = ring[i];
    const [xj, yj] = ring[j];
    const crosses = (yi > point[1]) !== (yj > point[1]) &&
      point[0] < ((xj - xi) * (point[1] - yi)) / ((yj - yi) || Number.EPSILON) + xi;
    if (crosses) inside = !inside;
  }
  return inside;
}

function installMapInteractions(map, popup) {
  let hoveredId = null;
  let popupId = null;
  map.on("mousemove", "connection-markers", (event) => {
    const feature = event.features?.[0];
    if (!feature) return;
    map.getCanvas().style.cursor = "pointer";
    if (popupId === feature.id) return;
    popupId = feature.id;
    popup.setLngLat(event.lngLat).setDOMContent(connectionPopup(feature.properties)).addTo(map);
  });
  map.on("mouseleave", "connection-markers", () => {
    map.getCanvas().style.cursor = "";
    popupId = null;
    popup.remove();
  });
  map.on("click", "connection-markers", (event) => {
    const key = event.features?.[0]?.properties?.connectionKey;
    if (typeof key === "string" && key.startsWith("connection:")) {
      document.dispatchEvent(new CustomEvent("wintcp:inspect-connection", { detail: { key } }));
    }
  });
  map.on("mousemove", "country-fill", (event) => {
    const feature = event.features?.[0];
    if (!feature) return;
    const id = feature.properties.iso2;
    if (hoveredId && hoveredId !== id) map.setFeatureState({ source: "countries", id: hoveredId }, { hover: false });
    hoveredId = id;
    map.setFeatureState({ source: "countries", id }, { hover: true });
  });
  map.on("mouseleave", "country-fill", () => {
    if (hoveredId) map.setFeatureState({ source: "countries", id: hoveredId }, { hover: false });
    hoveredId = null;
  });
}

export function connectionPopup(properties) {
  const root = document.createElement("div");
  root.className = "map-tooltip";
  const title = document.createElement("strong");
  title.textContent = properties.process || "Unknown process";
  root.append(title);
  const entries = [
    ["PID", properties.pid],
    ["Remote", `${properties.remote}${properties.port ? `:${properties.port}` : ""}`],
    ["DNS", properties.hostname],
    ["Country", properties.country],
    ["Location", properties.locationNote],
    ["Protocol", properties.protocol],
    ["State", properties.state],
  ];
  for (const [label, value] of entries) {
    if (!value) continue;
    const line = document.createElement("div");
    const key = document.createElement("span");
    key.className = "map-tooltip-label";
    key.textContent = `${label}: `;
    line.append(key, document.createTextNode(String(value)));
    root.append(line);
  }
  if (properties.connectionKey) {
    const inspect = document.createElement("button");
    inspect.type = "button";
    inspect.className = "btn btn-outline btn-sm map-inspect-action";
    inspect.textContent = "Open connection details";
    inspect.addEventListener("click", () => {
      document.dispatchEvent(new CustomEvent("wintcp:inspect-connection", {
        detail: { key: properties.connectionKey },
      }));
    });
    root.append(inspect);
  }
  return root;
}

function renderCountryList(container, countries, state) {
  if (!container) return;
  clear(container);
  if (!state.geoSummary?.geoIpConfigured) {
    container.append(emptyState({ action: { label: "Open Settings", href: "#/settings" } }, "GeoIP not configured", "Set a GeoIP database path in Settings to color countries and show connection markers."));
    return;
  }
  if (!countries.length) {
    container.append(emptyState({ action: { label: "View Network", href: "#/network" } }, "No remote peers resolved", "The current snapshot has no remote connections with a country match."));
    return;
  }
  const list = h("div", { class: "country-list" });
  for (const country of countries.slice(0, 20)) {
    list.append(h("div", { class: "country-row" },
      h("span", { class: "country-code" }, country.name),
      h("span", { class: "country-count num" }, fmtInt(country.count)),
    ));
  }
  container.append(list);
}

function cssColor(token, fallback) {
  const value = getComputedStyle(document.documentElement).getPropertyValue(token).trim();
  if (!value) return fallback;
  const canvas = cssColor.canvas || (cssColor.canvas = document.createElement("canvas"));
  canvas.width = canvas.height = 1;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  context.fillStyle = value;
  context.fillRect(0, 0, 1, 1);
  const [red, green, blue, alpha] = context.getImageData(0, 0, 1, 1).data;
  return `rgba(${red}, ${green}, ${blue}, ${alpha / 255})`;
}

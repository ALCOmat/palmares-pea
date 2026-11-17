"use strict";
/* Palmares PEA : lit le palmares (toutes les actions eligibles analysees) et fait les classements ici,
   avec les filtres : plus fortes hausses, actions a dividendes, veille financiere (note sur 10).
   Deux modes : la page du serveur local (api/...) ou le site publie sur GitHub Pages, sans serveur, dont
   l'index porte data-mode="statique" (pea.publier) : donnees lues dans donnees/, chiffrees. */

const $ = (id) => document.getElementById(id);
const STATIQUE = document.documentElement.dataset.mode === "statique";

// -- donnees : serveur local, ou site publie (en clair, ou chiffre : AES-256-GCM, cle tiree du mot de
// passe par PBKDF2-SHA256 ; voir pea/publier.py) ---------------------------------------------------------
const CHIFFRE = { actif: false, cle: null, params: null };
const STOCKAGE_CLE = "pea-cle-";
const octetsB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64Octets = (o) => btoa(String.fromCharCode(...o));

async function deriverCle(motDePasse, params) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(motDePasse), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: octetsB64(params.sel), iterations: params.iterations,
    hash: "SHA-256" }, base, 256);
  return new Uint8Array(bits);
}

async function dechiffrer(cle, tampon, nom) {
  const o = new Uint8Array(tampon);
  const clair = await crypto.subtle.decrypt({ name: "AES-GCM", iv: o.slice(0, 12), additionalData: new TextEncoder().encode(nom) },
    cle, o.slice(12));
  return new Response(new Blob([clair]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
}

async function essayerCle(brute) {                    // la cle dechiffre-t-elle le bloc de controle ?
  const cle = await crypto.subtle.importKey("raw", brute, { name: "AES-GCM" }, false, ["decrypt"]);
  try {
    if (await dechiffrer(cle, octetsB64(CHIFFRE.params.controle).buffer, "controle") !== "palmares-pea") return null;
  } catch { return null; }
  // cle des noms de fichiers d'analyse : SHA-256("noms|" + cle), comme pea/publier.py (nom_fichier_analyse)
  const prefixe = new TextEncoder().encode("noms|");
  const melange = new Uint8Array(prefixe.length + brute.length);
  melange.set(prefixe);
  melange.set(brute, prefixe.length);
  CHIFFRE.cleNoms = await crypto.subtle.importKey("raw", await crypto.subtle.digest("SHA-256", melange),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return cle;
}

async function nomFichierAnalyse(symbole) {
  if (!CHIFFRE.actif) return (/^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\.|$)/i.test(symbole) ? "_" : "") + symbole;
  const empreinte = new Uint8Array(await crypto.subtle.sign("HMAC", CHIFFRE.cleNoms, new TextEncoder().encode(symbole)));
  return [...empreinte].map((o) => o.toString(16).padStart(2, "0")).join("").slice(0, 24);
}

async function lire(nom, frais = false) {
  // nom : « palmares », « series » ou « analyses/<symbole> » ; rend le JSON
  const options = frais ? { cache: "no-store" } : undefined;
  let url;
  if (!STATIQUE) {
    url = nom === "palmares" ? "api/palmares" : "api/analyse?s=" + encodeURIComponent(nom.slice("analyses/".length));
  } else {
    const chemin = nom.startsWith("analyses/") ? "analyses/" + encodeURIComponent(await nomFichierAnalyse(nom.slice(9))) : nom;
    url = `donnees/${chemin}.${CHIFFRE.actif ? "bin" : "json"}`;
  }
  const r = await fetch(url, options);
  if (!r.ok) throw new Error(r.status === 404 ? "introuvable" : "HTTP " + r.status);
  if (!STATIQUE || !CHIFFRE.actif) return r.json();
  return JSON.parse(await dechiffrer(CHIFFRE.cle, await r.arrayBuffer(), nom));
}

async function preparerChiffrement() {
  // Site publie : donnees chiffrees si donnees/chiffrement.json existe ; cle gardee sur l'appareil.
  let r;
  try { r = await fetch("donnees/chiffrement.json", { cache: "no-store" }); } catch { r = null; }
  if (!r || !r.ok) {
    try { r = await fetch("donnees/chiffrement.json"); } catch { return; }     // hors connexion : copie du service worker
    if (!r.ok) return;
  }
  CHIFFRE.params = await r.json();
  CHIFFRE.actif = true;
  if (!window.crypto || !crypto.subtle || typeof DecompressionStream === "undefined") {
    message("Ce navigateur ne sait pas déchiffrer les données (iOS 16.4 ou plus récent nécessaire).");
    throw new Error("déchiffrement indisponible");
  }
  const cleStockage = STOCKAGE_CLE + CHIFFRE.params.sel;
  let gardee = null;
  try { gardee = localStorage.getItem(cleStockage); } catch { /* stockage indisponible */ }
  if (gardee) {
    CHIFFRE.cle = await essayerCle(octetsB64(gardee));
    if (CHIFFRE.cle) return;
  }
  CHIFFRE.cle = await demanderMotDePasse(cleStockage);
}

function demanderMotDePasse(cleStockage) {
  const dlg = $("verrou"), champ = $("verrou-mdp"), erreur = $("verrou-erreur"), bouton = $("verrou-ouvrir");
  dlg.addEventListener("cancel", (ev) => ev.preventDefault());       // pas de donnees sans mot de passe
  dlg.showModal();
  champ.focus();
  return new Promise((resoudre) => {
    $("verrou-formulaire").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      bouton.disabled = true;
      erreur.textContent = "Vérification…";
      const brute = await deriverCle(champ.value, CHIFFRE.params);
      const cle = await essayerCle(brute);
      bouton.disabled = false;
      if (!cle) {
        erreur.textContent = "Mot de passe incorrect.";
        champ.select();
        return;
      }
      try {
        Object.keys(localStorage).filter((k) => k.startsWith(STOCKAGE_CLE)).forEach((k) => localStorage.removeItem(k));
        localStorage.setItem(cleStockage, b64Octets(brute));
      } catch { /* navigation privee : il faudra le ressaisir */ }
      champ.value = "";
      erreur.textContent = "";
      dlg.close();
      resoudre(cle);
    });
  });
}

// -- constantes et etat -------------------------------------------------------------------------------------
const ORDRE_PLACES = ["Paris", "Amsterdam", "Bruxelles", "Lisbonne", "Milan", "Dublin", "Francfort", "Vienne", "Madrid",
  "Helsinki", "Oslo", "Stockholm", "Copenhague"];
const FREQUENCES = { 1: "annuel", 2: "semestriel", 3: "3 fois par an", 4: "trimestriel", 6: "6 fois par an", 12: "mensuel" };
const MOIS = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."];
const JOURS = ["dimanche", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi"];
const MOIS_LONGS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre",
  "novembre", "décembre"];
const ONGLETS = ["hausses", "dividendes", "veille", "favoris"];
// piliers de la note : cle, nom, nom court (colonnes de la veille)
const PILIERS = [["bilan", "Bilan et dette", "Bilan"], ["rentabilite", "Rentabilité", "Renta."],
  ["tresorerie", "Trésorerie et dividende", "Tréso."], ["croissance", "Croissance", "Croiss."], ["valorisation", "Valorisation", "Valo."]];
// pays de chaque place : le pays d'une action ne s'affiche que s'il differe (societe etrangere cotee la)
const PAYS_PLACE = { Paris: "FR", Amsterdam: "NL", Bruxelles: "BE", Lisbonne: "PT", Milan: "IT", Dublin: "IE", Francfort: "DE",
  Vienne: "AT", Madrid: "ES", Helsinki: "FI", Oslo: "NO", Stockholm: "SE", Copenhague: "DK" };
const STOCKAGE = "pea-filtres";
const STOCKAGE_FAVORIS = "pea-favoris";            // favoris : sur cet appareil seulement (navigateur)
const DEFAUTS = { cap: 0, adv: 1e6, secteur: "", perf: "perf_eur", tri: "rendement", regulier: true, sansPlaces: [],
  veille: "tops", onglet: "hausses" };

const etat = { palmares: null, series: { dates: [], valeurs: {} }, filtres: { ...DEFAUTS }, places: [], majConnue: null,
  enCours: false, minuterie: null, favoris: [], rangs: { perf: new Map(), div: new Map() }, fiche: null };

// -- formats ----------------------------------------------------------------------------------------
const NB = {};
function nombre(x, d) {
  NB[d] = NB[d] || new Intl.NumberFormat("fr-FR", { minimumFractionDigits: d, maximumFractionDigits: d });
  return NB[d].format(x);
}
function pct(x, d = 1, signe = true) {                // signe : « + » devant les hausses ; « − » toujours
  if (x == null || !isFinite(x)) return "—";
  const s = x < -0.00005 ? "−" : signe && x > 0.00005 ? "+" : "";
  return s + nombre(Math.abs(x * 100), d) + " %";
}
const pctCompact = (x) => pct(x, x != null && Math.abs(x) >= 1 ? 0 : 1);
const SYMBOLES = { EUR: "€" };                        // couronnes : NOK, SEK, DKK en toutes lettres
function montant(x, devise, d = 2) {
  if (x == null || !isFinite(x)) return "—";
  const dec = x >= 1000 ? 0 : x < 1 ? Math.max(d, 3) : d;
  return nombre(x, dec) + " " + (SYMBOLES[devise] || devise || "");
}
function grand(x) {
  if (x == null || !isFinite(x)) return "—";
  if (x >= 1e9) return nombre(x / 1e9, x >= 1e11 ? 0 : 1) + " Md€";
  if (x >= 1e6) return nombre(x / 1e6, x >= 1e8 ? 0 : 1) + " M€";
  return nombre(x / 1e3, 0) + " k€";
}
function dateCourte(iso, annee = true) {
  const d = new Date(iso + (iso.length === 10 ? "T12:00:00" : ""));
  return `${d.getDate()} ${MOIS[d.getMonth()]}${annee ? " " + d.getFullYear() : ""}`;
}
function dateLongue(iso) {
  const d = new Date(iso + "T12:00:00");
  return `${JOURS[d.getDay()]} ${d.getDate()} ${MOIS_LONGS[d.getMonth()]} ${d.getFullYear()}`;
}
function taux(t) {                                   // 30 -> "30", 27.5 -> "27,5", 26.375 -> "26,375"
  return Number.isInteger(t) ? String(t) : nombre(t, 3).replace(/0+$/, "");
}
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
// Nom sans la forme juridique de la fin (« AB (publ) », « Aktiengesellschaft », « S.p.A. », « SE & Co. KGaA »...) :
// listes plus lisibles ; le nom complet reste dans la fiche et l'infobulle.
const FORME_JURIDIQUE = new RegExp("[\\s,]+(?:\\(publ\\)|AB|ASA|AS|A/S|Oyj|Abp|Oy|S\\.?A\\.?|SA/NV|NV/SA|N\\.?V\\.?|"
  + "S\\.?p\\.?A\\.?|S\\.?G\\.?P\\.?S\\.?|S\\.?C\\.?A\\.?|SE|AG|KGaA|& Co\\.?|Aktiengesellschaft|Société anonyme|"
  + "Société européenne|plc|p\\.l\\.c\\.?|GmbH)\\.?$", "i");
function nomCourt(nom) {
  const complet = String(nom ?? "").trim();
  let n = complet, avant;
  do {
    avant = n;
    n = n.replace(FORME_JURIDIQUE, "").trim();
  } while (n !== avant);
  return n.length >= 2 ? n : complet;
}
const sansAccents = (s) => String(s ?? "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
const pluriel = (n, mot) => `${n} ${mot}${n > 1 ? "s" : ""}`;
const icone = (nom, t = 16) => `<svg width="${t}" height="${t}" aria-hidden="true"><use href="#i-${nom}"/></svg>`;

// -- messages, preferences, infobulle -----------------------------------------------------------------------
let minuterieMessage = null;
function message(texte, ephemere = false) {
  $("message").textContent = texte || "";
  clearTimeout(minuterieMessage);
  if (texte && ephemere) minuterieMessage = setTimeout(() => { $("message").textContent = ""; }, 6000);
}
function lirePreferences() {
  try {
    etat.filtres = { ...DEFAUTS, ...JSON.parse(localStorage.getItem(STOCKAGE) || "{}") };
  } catch { etat.filtres = { ...DEFAUTS }; }
  const ancre = location.hash.slice(1);
  if (ONGLETS.includes(ancre)) etat.filtres.onglet = ancre;
}
function garderPreferences() {
  try { localStorage.setItem(STOCKAGE, JSON.stringify(etat.filtres)); } catch { /* navigation privee */ }
}

// -- favoris : symboles dans l'ordre d'ajout, gardes dans le navigateur de cet appareil -------------------------
function lireFavoris() {
  try {
    const f = JSON.parse(localStorage.getItem(STOCKAGE_FAVORIS) || "[]");
    etat.favoris = Array.isArray(f) ? [...new Set(f.filter((s) => typeof s === "string" && s))] : [];
  } catch { etat.favoris = []; }
}
const estFavori = (s) => etat.favoris.includes(s);
function etoile(s, nom, fiche = false) {
  const fav = estFavori(s);
  return `<button type="button" class="etoile${fiche ? " etoile-fiche" : ""}" data-fav="${esc(s)}" data-nom="${esc(nom)}" aria-pressed="${fav}"`
    + ` aria-label="${esc(`${fav ? "Retirer" : "Ajouter"} ${nom} ${fav ? "des" : "aux"} favoris`)}" title="${fav ? "Retirer des favoris" : "Ajouter aux favoris"}">`
    + `${icone(fav ? "etoile-pleine" : "etoile", fiche ? 18 : 17)}${fiche ? `<span>${fav ? "Favori" : "Ajouter aux favoris"}</span>` : ""}</button>`;
}
function basculerFavori(s) {
  const i = etat.favoris.indexOf(s);
  if (i >= 0) etat.favoris.splice(i, 1); else etat.favoris.push(s);
  try { localStorage.setItem(STOCKAGE_FAVORIS, JSON.stringify(etat.favoris)); } catch { /* navigation privee */ }
  document.querySelectorAll(".etoile[data-fav]").forEach((b) => {
    if (b.dataset.fav === s) b.outerHTML = etoile(s, b.dataset.nom, b.classList.contains("etoile-fiche"));
  });
  rendreFavoris();
  chargerSeries(etat.favoris).then((nouvelles) => { if (nouvelles) rendreFavoris(); });
}
const bulle = $("infobulle");
function montrerBulle(texte, x, y) {
  bulle.textContent = texte;
  bulle.hidden = false;
  const r = bulle.getBoundingClientRect();
  bulle.style.left = Math.max(8, Math.min(x + 14, window.innerWidth - r.width - 8)) + "px";
  bulle.style.top = Math.max(8, y + 16 + r.height > window.innerHeight ? y - r.height - 12 : y + 16) + "px";
}
function cacherBulle() { bulle.hidden = true; }

// -- filtres ----------------------------------------------------------------------------------------------
function placesActives() {
  return new Set(etat.places.filter((p) => !etat.filtres.sansPlaces.includes(p)));
}
function filtrer(lignes) {
  const f = etat.filtres, places = placesActives();
  return lignes.filter((l) => places.has(l.place) && l.adv >= f.adv && (!f.cap || (l.cap != null && l.cap >= f.cap))
    && (!f.secteur || l.secteur === f.secteur));
}
function classementPerf(lignes) {
  const k = etat.filtres.perf;
  return lignes.filter((l) => l[k] != null).sort((a, b) => b[k] - a[k]);
}
function classementDiv(lignes) {
  const k = etat.filtres.tri, max = etat.palmares.reglages.rendement_max;
  return lignes.filter((l) => l.div && l.div.annuel > 0 && l.div[k] != null && l.div.rendement <= max
    && (!etat.filtres.regulier || l.div.regulier)).sort((a, b) => b.div[k] - a.div[k]);
}
function compterFiltres() {
  // filtres en vigueur, y compris celui des echanges par jour actif par defaut (1 M€)
  const f = etat.filtres, actifs = [];
  if (f.sansPlaces.length) actifs.push(`${pluriel(etat.places.length - f.sansPlaces.length, "place")} sur ${etat.places.length}`);
  if (f.cap) actifs.push(`capitalisation de ${grand(f.cap)} et plus`);
  if (f.adv) actifs.push(`${grand(f.adv)} et plus échangés par jour`);
  if (f.secteur) actifs.push(`secteur ${f.secteur}`);
  $("compte-filtres").textContent = actifs.length;
  $("compte-filtres").hidden = !actifs.length;
  $("bouton-filtres").title = actifs.length ? `Filtres en vigueur : ${actifs.join(", ")}` : "Aucun filtre";
}

function construirePuces() {
  const lignes = etat.palmares.lignes;
  const nb = {};
  for (const l of lignes) nb[l.place] = (nb[l.place] || 0) + 1;
  etat.places = ORDRE_PLACES.filter((p) => nb[p]).concat(Object.keys(nb).filter((p) => !ORDRE_PLACES.includes(p)));
  const actives = placesActives();
  const toutes = etat.places.every((p) => actives.has(p));
  const html = [`<button type="button" class="puce toutes" data-place="*" aria-pressed="${toutes}">Toutes</button>`];
  for (const p of etat.places) {
    html.push(`<button type="button" class="puce" data-place="${esc(p)}" aria-pressed="${actives.has(p)}">${esc(p)}`
      + `<span class="nb">${nb[p]}</span></button>`);
  }
  $("places").innerHTML = html.join("");
  const secteurs = [...new Set(lignes.map((l) => l.secteur).filter(Boolean))].sort((a, b) => a.localeCompare(b, "fr"));
  $("filtre-secteur").innerHTML = `<option value="">Tous</option>` + secteurs.map((s) => `<option>${esc(s)}</option>`).join("");
  if (!secteurs.includes(etat.filtres.secteur)) etat.filtres.secteur = "";
  $("filtre-secteur").value = etat.filtres.secteur;
  $("filtre-cap").value = String(etat.filtres.cap || 0);
  $("filtre-adv").value = String(etat.filtres.adv || 0);
  for (const [id, cle] of [["filtre-cap", "cap"], ["filtre-adv", "adv"]]) {
    if ($(id).selectedIndex < 0) $(id).selectedIndex = 0;
    etat.filtres[cle] = Number($(id).value);
  }
  $("filtre-regulier").checked = etat.filtres.regulier;
  $("tri-div").value = etat.filtres.tri;
  document.querySelectorAll("[data-perf]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.perf === etat.filtres.perf)));
  compterFiltres();
}

// -- elements graphiques ------------------------------------------------------------------------------------
function echelle(valeurs) {
  const bas = Math.min(0, ...valeurs), haut = Math.max(0, ...valeurs);
  return { bas, haut, etendue: haut - bas || 1 };
}
function piste(v, e) {
  const zero = ((0 - e.bas) / e.etendue) * 100, largeur = (Math.abs(v) / e.etendue) * 100;
  const gauche = v >= 0 ? zero : zero - largeur;
  return `<span class="piste" aria-hidden="true">${e.bas < 0 ? `<span class="zero" style="left:${zero}%"></span>` : ""}`
    + `<span class="rempli${v < 0 ? " bas" : ""}" style="left:${gauche}%;width:${Math.max(largeur, 1.2)}%"></span></span>`;
}

const COURBE = { L: 146, H: 40, m: 3 };
function courbe(symbole, L = COURBE.L, H = COURBE.H) {
  const valeurs = etat.series.valeurs[symbole], m = COURBE.m;
  if (!valeurs) return `<svg class="courbe" width="${L}" height="${H}" aria-hidden="true"></svg>`;
  const def = valeurs.map((v, i) => [i, v]).filter(([, v]) => v != null);
  if (def.length < 2) return `<svg class="courbe" width="${L}" height="${H}" aria-hidden="true"></svg>`;
  const vs = def.map(([, v]) => v);
  const bas = Math.min(1, ...vs), haut = Math.max(1, ...vs), etendue = haut - bas || 1;
  const n = valeurs.length - 1 || 1;
  const x = (i) => m + (i / n) * (L - 2 * m);
  const y = (v) => H - m - ((v - bas) / etendue) * (H - 2 * m);
  const d = def.map(([i, v], k) => `${k ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const premier = def[0], dernier = def[def.length - 1], fin = dernier[1];
  const sens = fin >= 1 ? "hausse" : "baisse";
  const aire = `${d}L${x(dernier[0]).toFixed(1)},${H}L${x(premier[0]).toFixed(1)},${H}Z`;
  const libelle = `Depuis le 31 décembre : ${pct(fin - 1)} (plus haut ${pct(Math.max(...vs) - 1)}, plus bas ${pct(Math.min(...vs) - 1)})`;
  return `<svg class="courbe" data-s="${esc(symbole)}" data-l="${L}" data-h="${H}" width="${L}" height="${H}" viewBox="0 0 ${L} ${H}" role="img" aria-label="${esc(libelle)}">`
    + `<path d="${aire}" fill="url(#deg-${sens})"/>`
    + `<line class="reference" x1="${m}" x2="${L - m}" y1="${y(1).toFixed(1)}" y2="${y(1).toFixed(1)}"/>`
    + `<path class="ligne-courbe" d="${d}" stroke="var(--${sens})"/>`
    + `<circle cx="${x(dernier[0]).toFixed(1)}" cy="${y(fin).toFixed(1)}" r="3" fill="var(--${sens})"/>`
    + `<circle class="point-survol" r="4.5" fill="var(--${sens})" visibility="hidden"/></svg>`;
}
function survolCourbe(svg, ev) {
  const valeurs = etat.series.valeurs[svg.dataset.s];
  if (!valeurs) return;
  const L = Number(svg.dataset.l), H = Number(svg.dataset.h), m = COURBE.m, n = valeurs.length - 1 || 1;
  const r = svg.getBoundingClientRect();
  let i = Math.round((((ev.clientX - r.left) / r.width) * L - m) / (L - 2 * m) * n);
  i = Math.max(0, Math.min(n, i));
  while (i > 0 && valeurs[i] == null) i--;
  if (valeurs[i] == null) return;
  const vs = valeurs.filter((v) => v != null);
  const bas = Math.min(1, ...vs), haut = Math.max(1, ...vs), etendue = haut - bas || 1;
  const point = svg.querySelector(".point-survol");
  point.setAttribute("cx", (m + (i / n) * (L - 2 * m)).toFixed(1));
  point.setAttribute("cy", (H - m - ((valeurs[i] - bas) / etendue) * (H - 2 * m)).toFixed(1));
  point.setAttribute("visibility", "visible");
  montrerBulle(`${i === 0 ? "31 déc." : dateCourte(etat.series.dates[i])} : ${pct(valeurs[i] - 1)}`, ev.clientX, ev.clientY);
}

function histogramme(l) {
  const par = l.div.par_an, annee = etat.palmares.annee;
  const annees = Object.keys(par).map(Number).sort((a, b) => a - b).slice(-11);
  const L = 11 * 9 - 2, H = 30, max = Math.max(...annees.map((a) => par[a])) || 1;
  const rects = annees.map((a, k) => {
    const v = par[a], x = (11 - annees.length + k) * 9;
    const h = v > 0 ? Math.max(2, (v / max) * (H - 2)) : 1.5;
    const cls = v <= 0 ? "annee nul" : a === annee ? "annee encours" : "annee";
    const texte = `${a} : ${v > 0 ? montant(v, l.devise) : "aucun versement"}${a === annee ? " (année en cours)" : ""}`;
    return `<rect class="${cls}" x="${x}" y="${H - h}" width="7" height="${h}" rx="1.5"/>`
      + `<rect class="cible" x="${x - 1}" y="0" width="9" height="${H}" data-bulle="${esc(texte)}"/>`;
  }).join("");
  return `<svg class="histo" width="${L}" height="${H}" viewBox="0 0 ${L} ${H}" role="img"`
    + ` aria-label="Dividende par année, de ${annees[0]} à ${annees[annees.length - 1]}">${rects}</svg>`;
}

function arcAnneau(note, r) {
  const c = 2 * Math.PI * r;
  return { c: c.toFixed(2), decalage: (c * (1 - Math.max(0, Math.min(10, note)) / 10)).toFixed(2) };
}
function qualificatif(note) {
  return note >= 7.5 ? "Très solide" : note >= 6 ? "Solide" : note >= 4.5 ? "Correcte" : note >= 3 ? "Fragile" : "Très fragile";
}
function anneau(l) {
  if (l.note == null) {
    return `<span class="sans-note" title="Pas d'analyse : comptes indisponibles, ou action hors du champ analysé">—</span>`;
  }
  const { c, decalage } = arcAnneau(l.note, 18);
  const titre = [`Note financière ${nombre(l.note, 1)}/10 (${qualificatif(l.note).toLowerCase()})${l.note_partielle ? ", partielle" : ""}`,
    ...(l.alertes || []).map((a) => "⚠ " + a)].join("\n");
  return `<button type="button" class="anneau" data-s="${esc(l.s)}" title="${esc(titre)}"`
    + ` aria-label="Analyse financière de ${esc(l.nom)} : ${nombre(l.note, 1)} sur 10${l.nb_alertes ? `, ${pluriel(l.nb_alertes, "alerte")}` : ""}">`
    + `<svg viewBox="0 0 44 44" width="44" height="44" aria-hidden="true"><circle class="piste-anneau" cx="22" cy="22" r="18" stroke-width="3.5"/>`
    + `<circle class="arc" cx="22" cy="22" r="18" stroke-width="3.5" stroke-dasharray="${c}" stroke-dashoffset="${decalage}"/></svg>`
    + `<span class="valeur-anneau">${nombre(l.note, 1)}${l.note_partielle ? "<sup>*</sup>" : ""}</span></button>`;
}
function celluleNote(l) {                          // anneau de la note, et le nombre d'alertes en toutes lettres
  const alertes = l.nb_alertes
    ? `<span class="nb-alertes" title="${esc((l.alertes || []).join("\n"))}">${icone("alerte", 12)}${pluriel(l.nb_alertes, "alerte")}</span>` : "";
  return `<div class="c-note">${anneau(l)}${alertes}</div>`;
}
function anneauSimple(note, taille = 46) {
  const r = taille / 2 - 4, { c, decalage } = arcAnneau(note ?? 0, r);
  return `<span class="anneau" style="width:${taille}px;height:${taille}px;cursor:inherit"><svg viewBox="0 0 ${taille} ${taille}" width="${taille}" height="${taille}" aria-hidden="true">`
    + `<circle class="piste-anneau" cx="${taille / 2}" cy="${taille / 2}" r="${r}" stroke-width="4"/>`
    + `<circle class="arc" cx="${taille / 2}" cy="${taille / 2}" r="${r}" stroke-width="4" stroke-dasharray="${c}" stroke-dashoffset="${decalage}"/></svg>`
    + `<span class="valeur-anneau">${note == null ? "—" : nombre(note, 1)}</span></span>`;
}

// -- lignes des classements ---------------------------------------------------------------------------------
function celluleSociete(l, marque = "") {
  const pays = etat.palmares.pays[l.pays] || l.pays;
  const titre = [l.nom, l.isin ? `ISIN ${l.isin}` : null, l.industrie, pays,
    l.autres ? `autre catégorie d'actions : ${l.autres.join(", ")}` : null].filter(Boolean).join(" · ");
  const etranger = PAYS_PLACE[l.place] && l.pays !== PAYS_PLACE[l.place];   // siege hors du pays de la place
  return `<div class="c-societe"><div class="titre-societe">${etoile(l.s, nomCourt(l.nom))}`
    + `<button type="button" class="nom" data-s="${esc(l.s)}" title="${esc(titre)}"><span class="nom-texte">${esc(nomCourt(l.nom))}</span></button></div>`
    + `<span class="meta"><a href="https://finance.yahoo.com/quote/${encodeURIComponent(l.s)}"`
    + ` target="_blank" rel="noopener noreferrer" title="Ouvrir la fiche Yahoo Finance">${esc(l.s)}</a>`
    + `<span>${esc(l.place)}</span>${l.segment ? `<span class="etiquette">${esc(l.segment)}</span>` : ""}`
    + `${etranger ? `<span title="Siège de la société">${esc(pays)}</span>` : ""}${marque}</span></div>`;
}
const classeLigne = () => "ligne cliquable";        // toute ligne ouvre sa fiche (cours, et analyse si elle existe)

function lignePerf(l, i, e, k) {
  const v = l[k];
  const local = l.devise !== "EUR" ? `<span class="sous">${pct(k === "perf_eur" ? l.perf : l.perf_tr)} en ${esc(l.devise)}</span>` : "";
  return `<li class="${classeLigne(l)}" data-s="${esc(l.s)}">
    <span class="c-rang">${i + 1}</span>${celluleSociete(l)}
    ${celluleNote(l)}
    <div class="c-secteur" title="${esc(l.industrie || "")}">${esc(l.secteur || "—")}</div>
    <div class="c-cours d"><span class="chiffre">${montant(l.cours, l.devise)}</span></div>
    <div class="c-valeur"><div class="haut"><span class="v${v < 0 ? " negatif" : ""}">${pctCompact(v)}</span>${local}</div>${piste(v, e)}</div>
    <div class="c-courbe">${courbe(l.s)}</div>
    <div class="c-cap d"><span class="chiffre">${grand(l.cap)}</span></div>
    <div class="c-adv d"><span class="chiffre">${grand(l.adv)}</span></div></li>`;
}

function ligneDiv(l, i, e) {
  const d = l.div, pays = etat.palmares.pays[l.pays] || l.pays;
  const marque = d.regulier ? "" : `<span class="alerte-div" title="${esc(d.motifs.join(" · "))}">non régulier</span>`;
  const ret = d.retenue == null ? "Taux de retenue à la source inconnu pour ce pays."
    : d.retenue === 0 ? `Pas de retenue à la source (${pays}).`
    : `Retenue à la source de ${taux(d.retenue)} % (${pays}), définitive dans un PEA.`;
  const exc = d.exceptionnel.length
    ? ` · <span title="${esc("Non compté : " + d.exceptionnel.map((x) => `${montant(x.montant, l.devise)} le ${dateCourte(x.date)}`).join(", "))}">+ exceptionnel</span>` : "";
  const depuis = d.consecutives ? `${d.consecutives}${d.depuis_min ? "+" : ""} an${d.consecutives > 1 ? "s" : ""}` : "—";
  return `<li class="${classeLigne(l)}" data-s="${esc(l.s)}">
    <span class="c-rang">${i + 1}</span>${celluleSociete(l, marque)}
    ${celluleNote(l)}
    <div class="c-valeur"><div class="haut"><span class="v">${pct(d.rendement, 2, false)}</span>`
      + `<span class="sous mobile-seul" title="${esc(ret)}">net PEA ${pct(d.net, 2, false)}</span></div>${piste(d.rendement, e)}</div>
    <div class="c-net d" title="${esc(ret)}"><span class="chiffre">${pct(d.net, 2, false)}</span></div>
    <div class="c-montant d"><span class="chiffre">${montant(d.annuel, l.devise)}</span>`
      + `<span class="sous">${FREQUENCES[d.frequence] || ""}${exc}<span class="mobile-seul"> · versé depuis ${d.depuis ?? "—"}</span></span></div>
    <div class="c-regularite" title="${esc(d.depuis_min ? `Versé chaque année depuis ${d.depuis} au moins (historique Yahoo)` : `Versé chaque année depuis ${d.depuis}`)}">`
      + `<span class="chiffre">${depuis}</span><span class="sous">depuis ${d.depuis ?? "—"}</span></div>
    <div class="c-cagr d">${d.cagr5 == null ? "—" : `<span class="chiffre${d.cagr5 < 0 ? " negatif" : ""}">${pct(d.cagr5)}</span><span class="sous">par an</span>`}</div>
    <div class="c-histo">${histogramme(l)}</div>
    <div class="c-payout d"><span class="chiffre">${d.payout == null ? "—" : pct(d.payout, 0, false)}</span><span class="sous">du bénéfice</span></div>
    <div class="c-perf2 d"><span class="chiffre${l.perf_eur < 0 ? " negatif" : ""}">${pct(l.perf_eur, 0)}</span></div></li>`;
}

function piliersMini(l) {
  return `<div class="piliers-mini">${PILIERS.map(([cle, nom, court]) => {
    const n = l.piliers ? l.piliers[cle] : null;
    return `<div class="pilier-mini" title="${esc(nom)} : ${n == null ? "non noté" : nombre(n, 1) + " sur 10"}">`
      + `<span class="colonne"><span style="height:${(n ?? 0) * 10}%"></span></span><b>${n == null ? "—" : nombre(n, 1)}</b>`
      + `<span class="etiq">${court}</span></div>`;
  }).join("")}</div>`;
}

function ligneVeille(l, i, rangPerf, rangDiv) {
  const presence = [rangPerf.has(l.s) ? `<span class="badge">${icone("hausse", 12)}Hausse n°${rangPerf.get(l.s)}</span>` : "",
    rangDiv.has(l.s) ? `<span class="badge">${icone("dividende", 12)}Dividendes n°${rangDiv.get(l.s)}</span>` : ""].join("");
  const al = l.alertes || [];
  const alertes = al.length
    ? `<div class="alerte-ligne">${icone("alerte", 15)}<span>${esc(al[0])}</span></div>`
      + (al.length > 1 ? `<span class="sous" title="${esc(al.slice(1).join("\n"))}">et ${al.length - 1} autre${al.length > 2 ? "s" : ""}</span>` : "")
    : `<span class="sous">aucune alerte</span>`;
  const evol = l.evol == null ? "—" : l.evol === 0 ? "="
    : `<span class="evol ${l.evol > 0 ? "monte" : "descend"}">${l.evol > 0 ? "▲" : "▼"} ${nombre(Math.abs(l.evol), 1)}</span>`;
  return `<li class="${classeLigne(l)}" data-s="${esc(l.s)}">
    <span class="c-rang">${i + 1}</span>${celluleSociete(l)}
    ${celluleNote(l)}
    <div class="c-evol d">${evol}</div>
    <div class="c-presence">${presence || '<span class="sous">—</span>'}</div>
    <div class="c-piliers">${piliersMini(l)}</div>
    <div class="c-alertes">${alertes}</div></li>`;
}

// -- rendu des panneaux --------------------------------------------------------------------------------------
function rendrePerf(filtrees) {
  const k = etat.filtres.perf;
  const tout = classementPerf(filtrees), top = tout.slice(0, 20);
  const e = echelle(top.map((l) => l[k]));
  $("entete-perf").textContent = k === "perf_tr_eur" ? "Hausse, dividendes réinvestis" : "Hausse du cours";
  $("liste-perf").innerHTML = top.map((l, i) => lignePerf(l, i, e, k)).join("");
  $("vide-perf").hidden = top.length > 0;
  $("precision-perf").textContent = `Top 20 en euros depuis le 31 décembre ${etat.palmares.annee - 1}`
    + (k === "perf_tr_eur" ? ", dividendes réinvestis" : "") + ` · parmi ${nombre(tout.length, 0)} actions qui passent les filtres`;
  return top;
}

function rendreDiv(filtrees) {
  const f = etat.filtres, k = f.tri;
  const tout = classementDiv(filtrees), top = tout.slice(0, 20);
  const e = echelle(top.map((l) => l.div.rendement));
  $("entete-div").textContent = "Rendement brut" + (k === "rendement" ? " ▼" : "");
  $("entete-net").textContent = "Net PEA" + (k === "net" ? " ▼" : "");
  $("entete-cagr").textContent = "Croissance 5 ans" + (k === "cagr5" ? " ▼" : "");
  $("liste-div").innerHTML = top.map((l, i) => ligneDiv(l, i, e)).join("");
  $("vide-div").hidden = top.length > 0;
  const mesure = { rendement: "Top 20 par rendement (dividende annuel courant / cours)", net: "Top 20 après retenue à la source étrangère (estimation)",
    cagr5: `Top 20 par croissance du dividende de ${etat.palmares.annee - 6} à ${etat.palmares.annee - 1}` }[k];
  $("precision-div").textContent = `${mesure} · parmi ${nombre(tout.length, 0)} actions`
    + (f.regulier ? " à dividende régulier" : " versant un dividende");
  return top;
}

function rendreVeille(filtrees, topPerf, topDiv) {
  const mode = etat.filtres.veille || "tops";
  const rangPerf = new Map(topPerf.map((l, i) => [l.s, i + 1])), rangDiv = new Map(topDiv.map((l, i) => [l.s, i + 1]));
  let suivies;
  if (mode === "tops") {
    const vues = new Map();
    for (const l of [...topPerf, ...topDiv]) vues.set(l.s, l);
    suivies = [...vues.values()];
  } else {
    suivies = filtrees;
  }
  const notees = suivies.filter((l) => l.note != null).sort((a, b) => b.note - a.note);
  const affichees = mode === "tops" ? notees : notees.slice(0, 100);
  $("liste-veille").innerHTML = affichees.map((l, i) => ligneVeille(l, i, rangPerf, rangDiv)).join("");
  $("vide-veille").hidden = affichees.length > 0;
  const sans = suivies.length - notees.length;
  $("precision-veille").textContent = mode === "tops"
    ? `${nombre(suivies.length, 0)} sociétés des deux top 20, classées par note sur 10` + (sans ? ` · ${sans} sans analyse` : "")
    : `Les ${nombre(affichees.length, 0)} meilleures notes parmi ${nombre(notees.length, 0)} actions analysées`;
  document.querySelectorAll("[data-veille]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.veille === mode)));
}

// -- favoris : toujours affiches, quels que soient les filtres ------------------------------------------------
function ligneFavori(l) {
  const v = l.perf_eur, d = l.div && l.div.annuel > 0 ? l.div : null, al = l.alertes || [];
  const local = l.devise !== "EUR" && l.perf != null ? `<span class="sous">${pct(l.perf)} en ${esc(l.devise)}</span>` : "";
  const alertes = l.note == null ? `<span class="sous">pas d'analyse financière</span>`
    : al.length ? `<div class="alerte-ligne">${icone("alerte", 15)}<span>${esc(al[0])}</span></div>`
      + (al.length > 1 ? `<span class="sous" title="${esc(al.slice(1).join("\n"))}">et ${pluriel(al.length - 1, "autre")}</span>` : "")
    : `<span class="sous">aucune alerte</span>`;
  const rend = d ? `<span class="mobile-seul">Rendement </span><span class="chiffre">${pct(d.rendement, 2, false)}</span>`
      + `<span class="sous">${d.net != null ? `net PEA ${pct(d.net, 2, false)}` : "brut"}</span>`
    : `<span class="sous">pas de dividende</span>`;
  return `<li class="${classeLigne(l)}" data-s="${esc(l.s)}">${celluleSociete(l)}
    ${celluleNote(l)}
    <div class="c-valeur"><div class="haut"><span class="v${v < 0 ? " negatif" : ""}">${pctCompact(v)}</span>${local}</div>
      <span class="sous mobile-seul">depuis le 1<sup>er</sup> janvier</span></div>
    <div class="c-courbe">${courbe(l.s)}</div>
    <div class="c-rend d${d ? "" : " sans"}">${rend}</div>
    <div class="c-alertes">${alertes}</div></li>`;
}

function rendreFavoris() {
  if (!etat.palmares) return;
  const parSymbole = new Map(etat.palmares.lignes.map((l) => [l.s, l]));
  $("liste-favoris").innerHTML = etat.favoris.map((s) => parSymbole.has(s) ? ligneFavori(parSymbole.get(s))
    : `<li class="ligne absente"><div class="c-societe"><div class="titre-societe">${etoile(s, s)}<span class="nom"><span class="nom-texte">${esc(s)}</span></span></div>`
      + `<span class="meta">Plus dans les données : plus éligible au PEA, ou plus cotée</span></div></li>`).join("");
  const n = etat.favoris.length;
  $("vide-favoris").hidden = n > 0;
  $("entete-favoris").hidden = !n;
  $("precision-favoris").textContent = n
    ? `${n} action${n > 1 ? "s" : ""} suivie${n > 1 ? "s" : ""}, dans l'ordre d'ajout · liste gardée sur cet appareil`
    : "Les actions suivies s'affichent ici, quels que soient les filtres";
}

function chercher(texte) {                           // nom, code ou ISIN, sans accents ; les plus echangees d'abord
  const q = sansAccents(texte).trim();
  if (!q || !etat.palmares) return [];
  const mots = q.split(/\s+/), trouves = [];
  for (const l of etat.palmares.lignes) {
    const nom = sansAccents(l.nom), code = sansAccents(l.s);
    if (!mots.every((m) => `${nom} ${code} ${sansAccents(l.isin)}`.includes(m))) continue;
    const rang = code === q || code.split(".")[0] === q ? 0 : code.startsWith(q) ? 1 : nom.startsWith(q) ? 2
      : nom.split(/[\s\-&.,']+/).some((w) => w.startsWith(mots[0])) ? 3 : 4;
    trouves.push([rang, l]);
  }
  return trouves.sort((a, b) => a[0] - b[0] || b[1].adv - a[1].adv).slice(0, 8).map(([, l]) => l);
}

function montrerResultats() {
  const champ = $("recherche"), boite = $("resultats");
  if (!champ.value.trim()) {
    boite.hidden = true;
    champ.setAttribute("aria-expanded", "false");
    return;
  }
  const trouves = chercher(champ.value);
  boite.innerHTML = trouves.length ? trouves.map((l) => {
    const fav = estFavori(l.s);
    return `<li><button type="button" class="resultat" data-ajout="${esc(l.s)}" aria-pressed="${fav}">${icone(fav ? "etoile-pleine" : "etoile", 18)}`
      + `<span class="resultat-texte"><span class="resultat-nom">${esc(nomCourt(l.nom))}</span>`
      + `<span class="resultat-meta">${esc(l.s)} · ${esc(l.place)}${l.note != null ? ` · note ${nombre(l.note, 1)}` : ""}</span></span>`
      + `<span class="resultat-action">${fav ? "Suivie" : "Ajouter"}</span></button></li>`;
  }).join("") : `<li class="resultat-vide">Aucune action éligible au PEA ne correspond.</li>`;
  boite.hidden = false;
  champ.setAttribute("aria-expanded", "true");
}
function fermerResultats() {
  $("resultats").hidden = true;
  $("recherche").setAttribute("aria-expanded", "false");
}

function rendreVitrine(topPerf, topDiv) {
  const p1 = topPerf[0], d1 = topDiv[0];
  const moyenne = (xs) => {
    const v = xs.map((l) => l.note).filter((n) => n != null);
    return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
  };
  const union = new Map();
  for (const l of [...topPerf, ...topDiv]) union.set(l.s, l);
  const signalees = [...union.values()].filter((l) => l.nb_alertes);
  const frequence = {};
  for (const l of signalees) for (const a of l.alertes || []) frequence[a] = (frequence[a] || 0) + 1;
  const courante = Object.entries(frequence).sort((a, b) => b[1] - a[1])[0];
  const k = etat.filtres.perf;
  const cartes = [
    p1 ? `<button type="button" class="carte-kpi" data-onglet="hausses">
      <span class="kpi-libelle">Plus forte hausse ${etat.palmares.annee}</span>
      <span class="kpi-valeur${p1[k] < 0 ? " negatif" : ""}">${pctCompact(p1[k])}</span>
      <span class="kpi-nom">${esc(nomCourt(p1.nom))}</span>
      <span class="kpi-detail">${esc(p1.place)} · ${esc(p1.secteur || "—")}</span>
      <span class="kpi-courbe">${courbe(p1.s, 104, 34)}</span></button>` : "",
    d1 ? `<button type="button" class="carte-kpi" data-onglet="dividendes">
      <span class="kpi-libelle">Meilleur rendement${etat.filtres.regulier ? " régulier" : ""}</span>
      <span class="kpi-valeur">${pct(d1.div.rendement, 1, false)}<small>net ${pct(d1.div.net, 1, false)}</small></span>
      <span class="kpi-nom">${esc(nomCourt(d1.nom))}</span>
      <span class="kpi-detail">${montant(d1.div.annuel, d1.devise)} par an · ${FREQUENCES[d1.div.frequence] || ""}</span></button>` : "",
    `<button type="button" class="carte-kpi" data-onglet="veille">
      <span class="kpi-libelle">Solidité financière moyenne</span>
      <span class="kpi-duo">
        <span>${anneauSimple(moyenne(topPerf))}<span class="libelle-anneau"><strong>Hausses</strong>top 20</span></span>
        <span>${anneauSimple(moyenne(topDiv))}<span class="libelle-anneau"><strong>Dividendes</strong>top 20</span></span>
      </span>
      <span class="kpi-detail">Note sur 10 tirée des comptes publiés</span></button>`,
    `<button type="button" class="carte-kpi" data-onglet="veille">
      <span class="kpi-libelle">Sous surveillance</span>
      <span class="kpi-valeur">${signalees.length}<small>sur ${union.size}</small></span>
      <span class="kpi-nom">sociétés des top 20 en alerte</span>
      <span class="kpi-detail">${courante ? `La plus fréquente : ${esc(courante[0].toLowerCase())}` : "Aucune alerte"}</span></button>`];
  $("vitrine").innerHTML = cartes.join("");
}

async function chargerSeries(symboles) {
  const manquants = symboles.filter((s) => !(s in etat.series.valeurs));
  if (!manquants.length) return false;
  if (STATIQUE) {                                     // site publie : toutes les courbes d'un coup (un fichier)
    if (etat.series.complet) return false;
    try {
      const d = await lire("series");
      etat.series = { dates: d.dates, valeurs: d.valeurs, complet: true };
      for (const s of manquants) if (!(s in etat.series.valeurs)) etat.series.valeurs[s] = null;
      return true;
    } catch { return false; }
  }
  try {
    const r = await fetch("api/series?s=" + encodeURIComponent(manquants.join(",")));
    if (!r.ok) return false;
    const d = await r.json();
    etat.series.dates = d.dates;
    for (const s of manquants) etat.series.valeurs[s] = d.valeurs[s] || null;
    return true;
  } catch { return false; }
}

async function rendre() {
  if (!etat.palmares) return;
  const filtrees = filtrer(etat.palmares.lignes);
  const topPerf = rendrePerf(filtrees);
  const topDiv = rendreDiv(filtrees);
  etat.rangs = { perf: new Map(topPerf.map((l, i) => [l.s, i + 1])), div: new Map(topDiv.map((l, i) => [l.s, i + 1])) };
  rendreVeille(filtrees, topPerf, topDiv);
  rendreVitrine(topPerf, topDiv);
  rendreFavoris();
  if (await chargerSeries([...topPerf.map((l) => l.s), ...etat.favoris])) {
    const encore = filtrer(etat.palmares.lignes);
    const top = rendrePerf(encore);
    rendreVitrine(top, classementDiv(encore).slice(0, 20));
    rendreFavoris();
  }
}

function squelettes() {
  for (const id of ["liste-perf", "liste-div", "liste-veille"]) {
    $(id).innerHTML = Array.from({ length: 7 }, () => `<li class="ligne-squelette squelette" aria-hidden="true"></li>`).join("");
  }
}

// -- onglets ------------------------------------------------------------------------------------------------
function afficherOnglet(nom, defiler = false) {
  if (!ONGLETS.includes(nom)) nom = "hausses";
  etat.filtres.onglet = nom;
  garderPreferences();
  document.querySelectorAll("[role=tab][data-onglet]").forEach((b) => {
    const actif = b.dataset.onglet === nom;
    b.setAttribute("aria-selected", String(actif));
    b.tabIndex = actif ? 0 : -1;
  });
  for (const n of ONGLETS) $("panneau-" + n).hidden = n !== nom;
  const favoris = nom === "favoris";                // les filtres ne s'appliquent pas aux favoris
  $("bouton-filtres").hidden = favoris;
  if (favoris) {
    $("filtres").hidden = true;
    $("bouton-filtres").setAttribute("aria-expanded", "false");
  }
  try { history.replaceState(null, "", "#" + nom); } catch { /* fichier local */ }
  if (defiler) {
    const haut = document.querySelector(".commandes-liste").getBoundingClientRect().top + window.scrollY - 76;
    if (window.scrollY > haut) window.scrollTo({ top: haut, behavior: "smooth" });
  }
}

// -- fiche d'analyse ------------------------------------------------------------------------------------
function valeurMesure(m) {
  const v = m.valeur;
  if (v == null) return "—";
  // valeurs reperes de pea/analyse.py (NEGATIFS = -9, RETOUR = 9, conversion -2 / -3, 99 et 9,99)
  const speciaux = { levier: v >= 99 ? "EBITDA négatif" : null, couverture: v >= 99 ? "pas d'intérêts" : null,
    gearing: v >= 99 ? "fonds propres négatifs" : null, ev_ebitda: v >= 99 ? "EBITDA négatif" : null,
    per: v < 0 ? "en pertes" : null, pb: null, roe: v === -9 ? "fonds propres négatifs" : null,
    conversion: v === -2 ? "perte, mais FCF positif" : v === -3 ? "perte et FCF négatif" : null,
    tendance: v === -8 ? "trésorerie nette, stable" : null,
    croissance_ebit: v === -9 ? "passé en perte" : v === 9 ? "revenu en bénéfice" : null,
    croissance_rn: v === -9 ? "passé en perte" : v === 9 ? "revenu en bénéfice" : null,
    couv_div: v >= 9.99 ? "FCF négatif" : null, payout: v >= 9.99 ? "résultat négatif" : null,
    autonomie: v > 10 ? "plus de 10 ans" : null };
  if (speciaux[m.cle]) return speciaux[m.cle];
  switch (m.format) {
    case "x": return nombre(v, v >= 100 ? 0 : 1) + " ×";
    case "pct": return pct(v, Math.abs(v) < 0.1 ? 1 : 0, false);
    case "pct2": return pct(v, 2, false);
    case "pct_an": return pct(v, 1) + " par an";
    case "dx": return (v > 0 ? "+" : v < 0 ? "−" : "") + nombre(Math.abs(v), 1);
    case "dpct": return (v > 0 ? "+" : v < 0 ? "−" : "") + nombre(Math.abs(v * 100), 1) + " pts";
    case "part": return pct(v, 0, false) + " des années";
    case "ans": return nombre(v, 1) + " ans";
    default: return nombre(v, 2);
  }
}

function enMillions(x) {
  if (x == null) return "—";
  const a = Math.abs(x);
  if (a < 1e3) return nombre(x, 0);                  // chiffre d'affaires nul ou minuscule : « 0 », pas « 0 k »
  return a >= 1e9 ? nombre(x / 1e9, 1) + " Md" : a >= 1e6 ? nombre(x / 1e6, 0) + " M" : nombre(x / 1e3, 0) + " k";
}

function petitGraphe(titre, annees, valeurs, fmt) {
  const L = 220, H = 96, haut = 10, bas = 16, n = annees.length;
  const vs = valeurs.filter((v) => v != null);
  if (!vs.length) return "";
  const mn = Math.min(0, ...vs), mx = Math.max(0, ...vs), et = mx - mn || 1;
  const y = (v) => haut + (mx - v) / et * (H - haut - bas);
  const pas = L / n, larg = Math.min(30, pas - 10);
  const barres = valeurs.map((v, i) => {
    const x = i * pas + (pas - larg) / 2;
    const etiquette = `<text x="${(x + larg / 2).toFixed(1)}" y="${H - 3}" text-anchor="middle" class="axe-texte">${esc(annees[i])}</text>`;
    if (v == null) return etiquette;
    const y0 = y(Math.max(v, 0)), h = Math.max(Math.abs(y(v) - y(0)), 1.5);
    return `<rect x="${x.toFixed(1)}" y="${y0.toFixed(1)}" width="${larg.toFixed(1)}" height="${h.toFixed(1)}" rx="3" class="${v < 0 ? "neg" : "pos"}">`
      + `<title>${esc(annees[i])} : ${esc(fmt(v))}</title></rect>${etiquette}`;
  }).join("");
  const derniere = valeurs[n - 1];                    // dernier exercice, meme s'il n'est pas calculable
  return `<figure class="petit-graphe"><figcaption>${esc(titre)}<span class="derniere">${derniere == null ? "n.s." : esc(fmt(derniere))}</span></figcaption>`
    + `<svg viewBox="0 0 ${L} ${H}" width="100%" height="${H}" role="img" aria-label="${esc(titre)} par exercice">`
    + `<line x1="0" x2="${L}" y1="${y(0).toFixed(1)}" y2="${y(0).toFixed(1)}" class="zero"/>${barres}</svg></figure>`;
}

// -- fiche : en-tete, cours depuis le 1er janvier, analyse financiere ------------------------------------------
function enteteFiche(l) {
  const pays = etat.palmares.pays[l.pays] || l.pays, r = etat.rangs;
  const rangs = (r.perf.has(l.s) ? `<span class="badge">${icone("hausse", 12)}Hausse n°${r.perf.get(l.s)}</span>` : "")
    + (r.div.has(l.s) ? `<span class="badge">${icone("dividende", 12)}Dividendes n°${r.div.get(l.s)}</span>` : "");
  return `<header class="feuille-entete">
      <div class="entete-texte"><h2 id="fiche-titre">${esc(l.nom)}</h2>
        <div class="detail">${rangs}<span class="badge">${esc(l.s)}</span><span class="badge">${esc(l.place)}</span><span class="badge">${esc(pays)}</span>`
        + `${l.secteur ? `<span class="badge">${esc(l.secteur)}</span>` : ""}${l.industrie ? `<span class="badge">${esc(l.industrie)}</span>` : ""}</div></div>
      <div class="entete-actions">${etoile(l.s, nomCourt(l.nom), true)}
        <button type="button" class="icone-btn" data-fermer aria-label="Fermer la fiche">${icone("fermer", 20)}</button></div>
    </header>`;
}

function blocCours(l) {
  const d = l.div && l.div.annuel > 0 ? l.div : null;
  const local = l.devise !== "EUR" && l.perf != null ? ` · ${pct(l.perf)} en ${l.devise}` : "";
  const chiffres = [
    ["Cours", montant(l.cours, l.devise), l.date ? `au ${dateCourte(l.date, false)}` : ""],
    ["Dividendes réinvestis", pctCompact(l.perf_tr_eur), "depuis le 1er janvier"],
    ["Capitalisation", grand(l.cap), ""],
    ["Échangé par jour", grand(l.adv), "en moyenne"],
    d && ["Rendement", pct(d.rendement, 2, false), d.net != null ? `net PEA ${pct(d.net, 2, false)}` : "brut"],
    d && ["Dividende", montant(d.annuel, l.devise), [FREQUENCES[d.frequence], d.depuis ? `versé depuis ${d.depuis}` : ""].filter(Boolean).join(" · ")],
  ].filter(Boolean);
  return `<section class="bloc bloc-cours">
      <h3>Depuis le 1<sup>er</sup> janvier</h3>
      <p class="cours-perf"><span class="grand-chiffre${l.perf_eur < 0 ? " negatif" : ""}">${pctCompact(l.perf_eur)}</span>`
      + `<span class="cours-precision">${esc("en euros" + local)}</span></p>
      <p class="lecture-cours" id="lecture-cours" aria-live="polite"></p>
      <div class="graphe-cours" id="graphe-cours"><div class="graphe-attente squelette"></div></div>
      <dl class="chiffres-cles">${chiffres.map(([t, v, s]) => `<div><dt>${t}</dt><dd>${esc(v)}${s ? `<span class="sous">${esc(s)}</span>` : ""}</dd></div>`).join("")}</dl>
    </section>`;
}

const MARGES = { h: 12, b: 24, g: 4, d: 54 };       // courbe de la fiche : haut, bas (mois), gauche, droite (graduations)
function graduations(bas, haut) {
  // domaine : les donnees avec un peu d'air ; graduations au pas « rond » (1, 2, 2,5 ou 5 x 10^k), 4 intervalles environ
  const etendue = haut - bas || 0.02;
  const brut = etendue / 4, p10 = 10 ** Math.floor(Math.log10(brut));
  const pas = [1, 2, 2.5, 5, 10].map((k) => k * p10).find((x) => x >= brut * (1 - 1e-9));
  const debut = bas - etendue * 0.06, fin = haut + etendue * 0.06, marques = [];
  for (let k = Math.ceil(debut / pas - 1e-9); k * pas <= fin + 1e-9; k++) marques.push(k * pas);
  return { pas, debut, fin, marques };
}
const dateSerie = (i) => (i === 0 ? "31 déc." : dateCourte(etat.series.dates[i], false));

function dessinerCours(l) {
  const boite = $("graphe-cours");
  if (!boite || etat.fiche !== l.s) return;
  const valeurs = etat.series.valeurs[l.s], m = MARGES;
  const def = (valeurs || []).map((v, i) => [i, v]).filter(([, v]) => v != null);
  if (def.length < 2) {
    boite.innerHTML = `<p class="note-bas">Courbe indisponible pour cette action.</p>`;
    $("lecture-cours").textContent = "";
    return;
  }
  const L = Math.max(240, Math.round(boite.clientWidth)), H = L < 520 ? 176 : 216;
  const g = graduations(Math.min(0, ...def.map(([, v]) => v - 1)), Math.max(0, ...def.map(([, v]) => v - 1)));
  const n = valeurs.length - 1 || 1;
  const x = (i) => m.g + (i / n) * (L - m.g - m.d);
  const y = (p) => m.h + ((g.fin - p) / (g.fin - g.debut)) * (H - m.h - m.b);
  const dec = Number.isInteger(Math.round(g.pas * 1000) / 10) ? 0 : 1;
  const grille = g.marques.map((p) => `<line class="${Math.abs(p) < 1e-9 ? "zero" : "grille"}" x1="${m.g}" x2="${L - m.d}" y1="${y(p).toFixed(1)}" y2="${y(p).toFixed(1)}"/>`
    + `<text class="axe" x="${L - m.d + 8}" y="${(y(p) + 4).toFixed(1)}">${pct(p, dec)}</text>`).join("");
  let derniere = -Infinity;                          // mois : premier point de chaque mois, etiquettes espacees
  const mois = [];
  for (let i = 1; i <= n; i++) {
    const a = new Date(etat.series.dates[i] + "T12:00:00"), b = new Date(etat.series.dates[i - 1] + "T12:00:00");
    if (a.getMonth() === b.getMonth() || x(i) - derniere < 36 || x(i) > L - m.d - 12) continue;
    derniere = x(i);
    mois.push(`<text class="axe" x="${x(i).toFixed(1)}" y="${H - 6}" text-anchor="middle">${MOIS[a.getMonth()]}</text>`);
  }
  const trace = def.map(([i, v], k) => `${k ? "L" : "M"}${x(i).toFixed(1)},${y(v - 1).toFixed(1)}`).join("");
  const premier = def[0], dernier = def[def.length - 1], sens = dernier[1] >= 1 ? "hausse" : "baisse";
  const fond = y(g.debut).toFixed(1);
  boite.innerHTML = `<svg class="courbe-fiche" width="${L}" height="${H}" viewBox="0 0 ${L} ${H}" role="img"`
    + ` aria-label="${esc(`Évolution depuis le 31 décembre, en euros : ${pct(dernier[1] - 1)}`)}">${grille}${mois.join("")}`
    + `<path d="${trace}L${x(dernier[0]).toFixed(1)},${fond}L${x(premier[0]).toFixed(1)},${fond}Z" fill="url(#deg-${sens})"/>`
    + `<path class="ligne-cours" d="${trace}" stroke="var(--${sens})"/>`
    + `<line class="viseur" y1="${m.h}" y2="${H - m.b}" visibility="hidden"/>`
    + `<circle class="point-fin" cx="${x(dernier[0]).toFixed(1)}" cy="${y(dernier[1] - 1).toFixed(1)}" r="4" fill="var(--${sens})"/>`
    + `<circle class="point-viseur" r="5" fill="var(--${sens})" visibility="hidden"/></svg>`;
  etat.graphe = { s: l.s, valeurs, n, L, x, y, actif: false };
  lectureParDefaut();
}
function lectureParDefaut() {
  const gph = etat.graphe;
  if (!gph || !$("lecture-cours")) return;
  const vs = gph.valeurs.map((v, i) => [i, v]).filter(([, v]) => v != null);
  const haut = vs.reduce((a, b) => (b[1] > a[1] ? b : a)), bas = vs.reduce((a, b) => (b[1] < a[1] ? b : a));
  $("lecture-cours").innerHTML = `Plus haut <b>${pctCompact(haut[1] - 1)}</b> (${dateSerie(haut[0])}) · plus bas `
    + `<b>${pctCompact(bas[1] - 1)}</b> (${dateSerie(bas[0])}) · cours de fin de semaine`;
}
function survolCours(ev) {                            // souris ou doigt sur la courbe : date et hausse a ce point
  const gph = etat.graphe;
  if (!gph) return;
  const svg = ev.target.closest ? ev.target.closest(".courbe-fiche") : null;
  if (!svg) {
    if (gph.actif) finSurvolCours();
    return;
  }
  const r = svg.getBoundingClientRect(), m = MARGES;
  let i = Math.round(((((ev.clientX - r.left) / r.width) * gph.L - m.g) / (gph.L - m.g - m.d)) * gph.n);
  i = Math.max(0, Math.min(gph.n, i));
  while (i > 0 && gph.valeurs[i] == null) i--;
  if (gph.valeurs[i] == null) return;
  gph.actif = true;
  const cx = gph.x(i).toFixed(1), viseur = svg.querySelector(".viseur"), point = svg.querySelector(".point-viseur");
  viseur.setAttribute("x1", cx);
  viseur.setAttribute("x2", cx);
  point.setAttribute("cx", cx);
  point.setAttribute("cy", gph.y(gph.valeurs[i] - 1).toFixed(1));
  viseur.setAttribute("visibility", "visible");
  point.setAttribute("visibility", "visible");
  $("lecture-cours").innerHTML = `${i === 0 ? "Le" : "Au"} ${dateSerie(i)} : <b>${pctCompact(gph.valeurs[i] - 1)}</b> depuis le 31 décembre`;
}
function finSurvolCours() {
  const gph = etat.graphe;
  if (!gph) return;
  gph.actif = false;
  document.querySelectorAll(".courbe-fiche .viseur, .courbe-fiche .point-viseur").forEach((e) => e.setAttribute("visibility", "hidden"));
  lectureParDefaut();
}

function analyseHtml(l, a) {
  const inf = a.infos, dev = inf.devise || "";
  const piliers = PILIERS.map(([cle]) => a.piliers[cle]).filter(Boolean);
  const { c, decalage } = arcAnneau(a.note, 58);
  const blocsPiliers = piliers.map((p) => `<div class="pilier"><span class="pilier-nom">${esc(p.libelle)}<span class="poids">${pct(p.poids, 0, false)}</span></span>`
    + `<span class="barre-pilier" aria-hidden="true"><span style="width:0" data-largeur="${(p.note ?? 0) * 10}%"></span></span>`
    + `<span class="pilier-note">${p.note == null ? "non noté" : nombre(p.note, 1)}</span></div>`).join("");
  const alertes = a.alertes.length
    ? `<section class="bloc bloc-alertes"><h3>Alertes</h3><ul class="liste-alertes">${a.alertes.map((t) => `<li>${icone("alerte", 16)}<span>${esc(t)}</span></li>`).join("")}</ul></section>`
    : `<section class="bloc bloc-ok">${icone("ok", 20)}<span>Aucune alerte sur les comptes publiés.</span></section>`;
  const fin = ["banque", "assurance", "financiere"].includes(a.grille);
  const captive = Boolean(inf.captive);               // dette et flux consolides avec la banque captive : pas montres
  const s = a.series;
  const graphes = [petitGraphe(`Chiffre d'affaires (${dev})`, s.exercices, s.ca, enMillions),
    fin ? "" : petitGraphe("Marge opérationnelle", s.exercices, s.marge_op, (v) => pct(v, 1, false)),
    fin || captive ? petitGraphe(`Résultat net (${dev})`, s.exercices, s.rn, enMillions) : "",
    fin || captive ? "" : petitGraphe("Dette nette / EBITDA", s.exercices, s.levier, (v) => nombre(v, 1) + " ×"),
    fin || captive ? "" : petitGraphe(`Flux de trésorerie disponible (${dev})`, s.exercices, s.fcf, enMillions)].join("");
  const mesures = piliers.map((p) => `<tbody><tr class="groupe"><th colspan="3" scope="rowgroup">${esc(p.libelle)}</th></tr>`
    + p.mesures.map((m) => `<tr><td>${esc(m.libelle)}</td><td class="d">${esc(valeurMesure(m))}</td>`
      + `<td class="d">${m.note == null ? `<span class="sans-note" title="${m.valeur == null ? "donnée absente" : "non significatif pour cette société"}">${m.valeur == null ? "—" : "n.s."}</span>`
        : `<span class="mini-barre" aria-hidden="true"><span style="width:${m.note * 10}%"></span></span>${nombre(m.note, 1)}`}</td></tr>`).join("")
    + `</tbody>`).join("");
  const h = a.historique || [];
  const historique = h.length >= 2
    ? `<div class="historique">${h.slice(-10).map(([d, n]) => `<span>${dateCourte(d, false)} · <b>${nombre(n, 1)}</b></span>`).join("")}</div>`
    : `<p class="note-bas">Première analyse le ${h.length ? dateCourte(h[0][0]) : "—"} : l'évolution s'affichera aux prochaines mises à jour.</p>`;
  const puces = (titre, liste, cls) => liste.length
    ? `<div class="${cls}"><h4>${titre}</h4><ul>${liste.map((t) => `<li>${esc(t)}</li>`).join("")}</ul></div>` : "";
  return `<div class="fiche-analyse" id="fiche-analyse"><h3 class="titre-fiche">Note financière sur 10</h3>
    <div class="fiche-haut">
      <div class="jauge">
        <div class="grand-anneau"><svg viewBox="0 0 132 132" width="132" height="132" aria-hidden="true">
          <circle class="piste-anneau" cx="66" cy="66" r="58" stroke-width="9"/>
          <circle class="arc" cx="66" cy="66" r="58" stroke-width="9" stroke-dasharray="${c}" stroke-dashoffset="${c}" data-decalage="${decalage}"/></svg>
          <span class="v">${nombre(a.note, 1)}<small>/10</small></span></div>
        <span class="qualificatif">${qualificatif(a.note)}</span>
        ${a.partielle ? `<span class="partielle">Note partielle : données incomplètes</span>` : ""}
      </div>
      <div class="piliers">${blocsPiliers}</div>
    </div>
    <p class="fiche-meta">Grille : ${esc(a.grille_nom)} · comptes au ${dateCourte(inf.exercice)} en ${esc(dev)} · ${inf.exercices} exercices</p>
    ${alertes}
    <section class="bloc"><h3>Lecture d'analyste</h3><ul class="lecture">${a.commentaire.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>
      <div class="forts-faibles">${puces("Points forts", a.forts, "forts")}${puces("Points faibles", a.faibles, "faibles")}</div></section>
    <section class="bloc"><h3>Sur ${inf.exercices} exercices</h3><div class="graphes">${graphes}</div></section>
    <section class="bloc"><h3>Détail des mesures</h3><table class="mesures"><thead><tr><th scope="col">Mesure</th>`
    + `<th scope="col" class="d">Valeur</th><th scope="col" class="d">Note</th></tr></thead>${mesures}</table></section>
    <section class="bloc"><h3>Historique de la note</h3>${historique}</section>
    <p class="note-bas">Note calculée à partir des comptes annuels publiés (Yahoo Finance), selon une grille fixe : une mesure de
      solidité et de qualité financière, pas une recommandation d'achat ou de vente.</p></div>`;
}

async function ouvrirFiche(symbole) {
  // Toute action a sa fiche : cours depuis le 1er janvier, puis l'analyse financiere si elle existe.
  const l = etat.palmares && etat.palmares.lignes.find((x) => x.s === symbole);
  if (!l) return;
  const r = etat.palmares.reglages, dlg = $("fiche");
  etat.fiche = l.s;
  etat.graphe = null;
  const analyse = l.note != null
    ? `<div class="fiche-analyse" id="fiche-analyse"><p class="chargement">Chargement de l'analyse…</p></div>`
    : `<section class="bloc bloc-info">${icone("info", 20)}<span>Pas d'analyse financière pour cette action : seules sont notées
        celles qui échangent au moins ${grand(r.analyse_adv_min)} par jour et les ${r.analyse_top} premières de chaque classement,
        si leurs comptes annuels sont publiés.</span></section>`;
  $("fiche-corps").innerHTML = enteteFiche(l) + blocCours(l) + analyse;
  if (!dlg.open) dlg.showModal();
  dlg.scrollTop = 0;
  chargerSeries([l.s]).catch(() => false).then(() => dessinerCours(l));
  if (l.note == null) return;
  let a;
  try {
    a = await lire("analyses/" + symbole);
  } catch (err) {
    const zone = etat.fiche === l.s ? $("fiche-analyse") : null;
    if (zone) {
      zone.innerHTML = `<p class="chargement">Analyse indisponible : ${esc(err.message === "introuvable"
        ? "pas d'analyse pour cette action" : err.message)}.</p>`;
    }
    return;
  }
  const zone = $("fiche-analyse");
  if (etat.fiche !== l.s || !zone) return;            // une autre fiche a ete ouverte entre-temps
  zone.outerHTML = analyseHtml(l, a);
  requestAnimationFrame(() => requestAnimationFrame(() => {     // anneau et barres se remplissent
    const arc = dlg.querySelector(".grand-anneau .arc");
    if (arc) arc.style.strokeDashoffset = arc.dataset.decalage;
    dlg.querySelectorAll("[data-largeur]").forEach((b) => { b.style.width = b.dataset.largeur; });
  }));
}

// -- methode ----------------------------------------------------------------------------------------------
function rendreMethode() {
  const p = etat.palmares, r = p.reglages, c = p.comptes;
  const exclusions = Object.entries(c.exclusions).map(([m, n]) => `<tr><td>${esc(m)}</td><td class="d">${nombre(n, 0)}</td></tr>`).join("");
  const retenues = Object.entries(p.retenues).filter(([pays]) => p.lignes.some((l) => l.pays === pays))
    .sort((a, b) => a[1] - b[1]).map(([pays, t]) => `<tr><td>${esc(p.pays[pays] || pays)}</td><td class="d">${taux(t)} %</td></tr>`).join("");
  const avert = (p.avertissements || []).map((a) => `<li>${esc(a)}</li>`).join("");
  $("methode-corps").innerHTML = `
    <section>
      <h3>Éligibilité au PEA (estimée)</h3>
      <p>Siège de la société dans l'Union européenne ou en Islande, au Liechtenstein ou en Norvège (pays de l'Espace
        économique européen admis par le fisc) : pays de l'ISIN, ou pays du siège selon Yahoo pour Madrid, Helsinki,
        Stockholm et Copenhague (une société étrangère cotée là est comptée sur sa place d'origine). Une forme
        juridique étrangère à la fin du nom (« Inc. », « Limited », « plc » hors Irlande, Chypre et Malte) trahit une
        société hors UE cotée sous un code européen ; les îles Féroé sont hors UE. Sont exclues les foncières cotées
        (régimes SIIC, SIR, SOCIMI, FBI, SIIQ, REIT, exonérés d'impôt sur les sociétés) et les sociétés
        d'investissement au même régime (pricaf, sicaf), les actions de préférence (refusées dans un PEA depuis 2014 :
        « PREF », « Vz » allemandes, « RSP » italiennes), les certificats (caisses d'épargne norvégiennes, certificats
        de dépôt suédois) et les fonds cotés. Une ligne par société : la catégorie d'actions la plus échangée. Toutes
        les places ne sont pas accessibles dans tous les PEA.</p>
    </section>
    <section>
      <h3>Hausse depuis le 1<sup>er</sup> janvier</h3>
      <p>Dernier cours / dernier cours de ${p.annee - 1} − 1, en euros (les actions cotées en couronnes ou en dollars
        sont converties ; la hausse en devise locale s'affiche dessous). « Dividendes réinvestis » : même calcul sur le
        cours ajusté des dividendes. Sont écartées les actions introduites en ${p.annee}, celles échangeant moins de
        ${grand(r.adv_min)} par jour en moyenne, et les données douteuses (pic d'un jour aussitôt défait, écart avec le cours de la bourse).</p>
    </section>
    <section>
      <h3>Dividendes</h3>
      <p>Dividende annuel courant : somme des derniers versements sur un an de fréquence habituelle (estimée sur 3 ans) ;
        un versement en plus, 2,5 fois plus gros que d'habitude, est compté comme exceptionnel et retiré.
        Rendement = dividende annuel courant / dernier cours.</p>
      <p>« Dividende régulier » : versé chacune des ${r.annees_regulieres} dernières années, sans baisse de plus de
        ${pct(r.baisse_max, 0, false)} d'une année sur l'autre ni en cours, sans hausse inhabituelle (plus de
        ${nombre(r.hausse_max, 1)} fois la moyenne des 3 dernières années), distribution d'au plus ${pct(r.payout_max, 0, false)} du
        bénéfice quand Yahoo la donne. Les rendements de plus de ${pct(r.rendement_max, 0, false)} ne sont jamais classés (à vérifier).</p>
    </section>
    <section>
      <h3>Note financière sur 10 (veille)</h3>
      <p>Calculée sur les comptes annuels publiés (4 à 5 exercices) de ${nombre(p.analysees || 0, 0)} sociétés : celles qui
        échangent au moins ${grand(r.analyse_adv_min)} par jour et les ${r.analyse_top} premières de chaque classement. Cinq piliers :
        bilan et dette (30 %), rentabilité (25 %), trésorerie et dividende (20 %), croissance (10 %), valorisation (15 %).
        Chaque mesure (dette nette / EBITDA, couverture des intérêts, rentabilité des capitaux employés, flux de trésorerie
        disponible, couverture du dividende, PER…) est notée de 0 à 10 par paliers fixes.</p>
      <p>Grilles propres aux banques et assurances (fonds propres / bilan, rentabilité des fonds propres et des actifs,
        distribution) et aux foncières (dette / valeur des actifs). Chez les constructeurs automobiles et de machines, la dette
        de la banque captive fausse le levier : il n'est pas noté. * = note partielle (données incomplètes).
        Une note mesure la solidité financière : ce n'est pas une recommandation.</p>
    </section>
    <section>
      <h3>Favoris</h3>
      <p>Une étoile à côté du nom, dans les listes ou la fiche, suit une action dans l'onglet Favoris, quels que soient les
        filtres ; la recherche de cet onglet trouve toute action éligible par son nom, son code ou son ISIN. La liste est
        gardée dans le navigateur de cet appareil : celle de l'iPhone et celle du PC sont distinctes.</p>
    </section>
    <section>
      <h3>Rendement net PEA (estimé)</h3>
      <p>Dans un PEA, la retenue à la source étrangère est perdue (le crédit d'impôt n'y est pas utilisable) ;
        les dividendes français n'en subissent aucune. Taux légaux appliqués sans démarche de remboursement :</p>
      <table>${retenues}</table>
    </section>
    <section>
      <h3>Données du ${dateCourte(p.maj.slice(0, 10))} à ${p.maj.slice(11, 16)}</h3>
      <p>Listes : Euronext (Paris, Amsterdam, Bruxelles, Lisbonne, Milan, Dublin, Oslo), Deutsche Börse (Xetra),
        filtre d'actions Yahoo (Madrid, Helsinki, Stockholm, Copenhague), Vienne. Cours, dividendes et fiches : Yahoo Finance
        (cours différés). ${nombre(c.cotations, 0)} actions examinées, ${nombre(c.eligibles, 0)} retenues. Écartées :</p>
      <table>${exclusions}</table>
      ${avert ? `<ul>${avert}</ul>` : ""}
    </section>`;
}

// -- donnees et etat ------------------------------------------------------------------------------------------
async function chargerPalmares(frais = false) {
  try {
    const p = await lire("palmares", frais);
    if (p.absent) { etat.palmares = null; return false; }
    etat.palmares = p;
    etat.majConnue = etat.palmares.maj;
    etat.series = { dates: [], valeurs: {} };
    return true;
  } catch (err) {
    message("Lecture des données impossible : " + err.message);
    return false;
  }
}

function afficherEntete() {
  const p = etat.palmares;
  if (!p) {
    $("sous-titre").textContent = "Pas encore de données";
    return;
  }
  // texte court sur telephone : la date entiere, sans l'annee ni le nombre d'actions
  const d = new Date(p.date_cours + "T12:00:00");
  $("sous-titre").innerHTML = `<span class="sous-long">Cours du ${dateLongue(p.date_cours)} · ${nombre(p.comptes.eligibles, 0)} actions éligibles</span>`
    + `<span class="sous-court">Cours du ${d.getDate()} ${MOIS_LONGS[d.getMonth()]}</span>`;
}

async function toutAfficher() {
  afficherEntete();
  construirePuces();
  rendreMethode();
  await rendre();
}

function afficherEtat(e) {
  const statut = $("statut"), texte = statut.querySelector(".texte");
  const maj = e.maj, fichier = e.fichier;
  etat.enCours = maj.en_cours;
  $("bouton-maj").disabled = maj.en_cours;
  if (maj.en_cours) {
    statut.dataset.etat = "maj";
    texte.textContent = "Mise à jour…";
    $("progression").hidden = false;
    $("progression-etape").textContent = maj.etape ? `Étape ${maj.n_etape} sur ${maj.n_etapes} · ${maj.etape}` : "Démarrage";
    $("progression-detail").textContent = maj.total ? `${nombre(maj.fait, 0)} / ${nombre(maj.total, 0)}` : "";
    const avance = maj.n_etape ? ((maj.n_etape - 1) + (maj.total ? maj.fait / maj.total : 0)) / maj.n_etapes : 0;
    $("progression-remplie").style.width = (100 * avance).toFixed(1) + "%";
  } else {
    $("progression").hidden = true;
    if (fichier && fichier.maj) {
      const age = (Date.now() - new Date(fichier.maj).getTime()) / 3600e3;
      statut.dataset.etat = age > 24 ? "ancien" : "frais";
      texte.textContent = `Données du ${dateCourte(fichier.maj.slice(0, 10), false)} à ${fichier.maj.slice(11, 16)}`;
    } else {
      statut.dataset.etat = "";
      texte.textContent = "Pas encore de données";
    }
    if (maj.erreur) message("La dernière mise à jour a échoué : " + maj.erreur);
    else if (maj.publication && etat.enCoursAvant) message(maj.publication, true);   // fin d'une mise a jour
  }
  etat.enCoursAvant = maj.en_cours;
  if (!etat.palmares) {
    message(maj.en_cours ? "Première mise à jour : 5 à 10 minutes, la page s'affichera toute seule."
      : maj.erreur ? $("message").textContent
      : "Pas encore de données : cliquez sur « Mettre à jour » (5 à 10 minutes).");
  }
}

function afficherEtatStatique() {
  const statut = $("statut"), p = etat.palmares;
  statut.dataset.etat = p && (Date.now() - new Date(p.maj).getTime()) / 3600e3 <= 36 ? "frais" : "ancien";
  statut.querySelector(".texte").textContent = p ? `Données du ${dateCourte(p.maj.slice(0, 10), false)} à ${p.maj.slice(11, 16)}`
    : "Pas encore de données";
}

// -- site publie : nouvelle version de l'app, nouvelles donnees ------------------------------------------------
function surveillerMisesAJour() {
  // Le service worker d'une nouvelle version prend la main tout de suite : la page se recharge alors pour
  // l'afficher (pas a la toute premiere installation, ni pendant une fiche ou la saisie du mot de passe).
  if (!("serviceWorker" in navigator)) return;
  const avaitControleur = Boolean(navigator.serviceWorker.controller);
  let recharge = false;
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (!avaitControleur || recharge) return;
    recharge = true;
    const ouverte = ["fiche", "methode", "verrou"].map($).find((d) => d.open);
    if (ouverte) ouverte.addEventListener("close", () => location.reload(), { once: true });
    else location.reload();
  });
  etat.derniereVerification = Date.now();
  navigator.serviceWorker.register("sw.js").then((enregistrement) => {
    // Sur l'iPhone, l'app reste en memoire : en y revenant, chercher une nouvelle version et de nouvelles donnees.
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState !== "visible" || Date.now() - etat.derniereVerification < 10 * 60e3) return;
      etat.derniereVerification = Date.now();
      enregistrement.update().catch(() => { /* hors connexion */ });
      verifierDonnees();
    });
  }).catch(() => { /* hors connexion : facultatif */ });
}

async function verifierDonnees() {                   // nouvelles donnees publiees depuis l'ouverture ?
  if (!etat.palmares || (CHIFFRE.actif && !CHIFFRE.cle)) return;
  try {
    const p = await lire("palmares", true);
    if (!p || p.absent || p.maj === etat.palmares.maj) return;
    etat.palmares = p;
    etat.majConnue = p.maj;
    etat.series = { dates: [], valeurs: {} };
    await toutAfficher();
    afficherEtatStatique();
    message("Nouvelles données chargées.", true);
  } catch { /* hors connexion : on garde ce qui est affiche */ }
}

async function actualiserStatique() {                 // site publie : relit les donnees sans cache
  $("bouton-maj").disabled = true;
  const avant = etat.palmares && etat.palmares.maj;
  if (await chargerPalmares(true)) {
    await toutAfficher();
    message(etat.palmares.maj === avant ? "Déjà à jour : le PC publie les données chaque soir de semaine."
      : "Nouvelles données chargées.", true);
  }
  afficherEtatStatique();
  $("bouton-maj").disabled = false;
}

async function lireEtat() {
  if (STATIQUE) return afficherEtatStatique();
  let prochain = 30000;
  try {
    const r = await fetch("api/etat");
    const e = await r.json();
    afficherEtat(e);
    if (e.fichier && e.fichier.maj && e.fichier.maj !== etat.majConnue) {
      if (await chargerPalmares()) {
        message("");
        await toutAfficher();
      }
    }
    if (e.maj.en_cours) prochain = 2000;
  } catch {
    $("statut").dataset.etat = "";
    $("statut").querySelector(".texte").textContent = "Serveur injoignable";
    prochain = 5000;
  }
  clearTimeout(etat.minuterie);
  etat.minuterie = setTimeout(lireEtat, prochain);
}

async function mettreAJour() {
  if (STATIQUE) return actualiserStatique();
  $("bouton-maj").disabled = true;
  try {
    const r = await fetch("api/mettre_a_jour", { method: "POST", headers: { "X-Pea": "1" } });
    const d = await r.json();
    message(d.message || d.erreur || "", true);
  } catch (err) {
    message("Mise à jour impossible : " + err.message);
  }
  lireEtat();
}

// -- evenements ---------------------------------------------------------------------------------------------
function brancher() {
  $("bouton-maj").addEventListener("click", mettreAJour);
  $("bouton-methode").addEventListener("click", () => $("methode").showModal());
  $("bouton-filtres").addEventListener("click", () => {
    const ouvert = $("filtres").hidden;
    $("filtres").hidden = !ouvert;
    $("bouton-filtres").setAttribute("aria-expanded", String(ouvert));
  });
  $("reinit-filtres").addEventListener("click", () => {
    Object.assign(etat.filtres, { sansPlaces: [], cap: 0, adv: DEFAUTS.adv, secteur: "" });
    garderPreferences();
    construirePuces();
    rendre();
  });
  $("places").addEventListener("click", (ev) => {
    const b = ev.target.closest(".puce");
    if (!b) return;
    // Tout est coche : un clic ne garde que cette place ; ensuite chaque clic ajoute ou retire une place.
    const p = b.dataset.place, actives = placesActives();
    if (p === "*") {
      etat.filtres.sansPlaces = [];
    } else if (actives.size === etat.places.length) {
      etat.filtres.sansPlaces = etat.places.filter((x) => x !== p);
    } else {
      if (actives.has(p)) actives.delete(p); else actives.add(p);
      etat.filtres.sansPlaces = actives.size ? etat.places.filter((x) => !actives.has(x)) : [];
    }
    garderPreferences();
    construirePuces();
    rendre();
  });
  const change = (id, cle, conv = (v) => v) => $(id).addEventListener("change", (ev) => {
    etat.filtres[cle] = conv(ev.target.type === "checkbox" ? ev.target.checked : ev.target.value);
    garderPreferences();
    compterFiltres();
    rendre();
  });
  change("filtre-cap", "cap", Number);
  change("filtre-adv", "adv", Number);
  change("filtre-secteur", "secteur");
  change("filtre-regulier", "regulier");
  change("tri-div", "tri");
  $("choix-perf").addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-perf]");
    if (!b) return;
    etat.filtres.perf = b.dataset.perf;
    document.querySelectorAll("[data-perf]").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    garderPreferences();
    rendre();
  });
  document.querySelectorAll("[data-veille]").forEach((b) => b.addEventListener("click", () => {
    etat.filtres.veille = b.dataset.veille;
    garderPreferences();
    rendre();
  }));
  // onglets : clic, fleches du clavier ; cartes de la vitrine
  const onglets = [...document.querySelectorAll("[role=tab][data-onglet]")];
  onglets.forEach((b, i) => {
    b.addEventListener("click", () => afficherOnglet(b.dataset.onglet, true));
    b.addEventListener("keydown", (ev) => {
      const pas = ev.key === "ArrowRight" ? 1 : ev.key === "ArrowLeft" ? -1 : 0;
      if (!pas) return;
      const cible = onglets[(i + pas + onglets.length) % onglets.length];
      cible.focus();
      afficherOnglet(cible.dataset.onglet);
    });
  });
  $("vitrine").addEventListener("click", (ev) => {
    const carte = ev.target.closest("[data-onglet]");
    if (carte) afficherOnglet(carte.dataset.onglet, true);
  });
  // lignes : l'etoile suit ou ne suit plus l'action ; le reste de la ligne ouvre sa fiche
  document.addEventListener("click", (ev) => {
    const ajout = ev.target.closest(".resultat[data-ajout]");
    if (ajout) {
      basculerFavori(ajout.dataset.ajout);
      montrerResultats();
      return;
    }
    if (!ev.target.closest(".recherche")) fermerResultats();
    const fav = ev.target.closest(".etoile[data-fav]");
    if (fav) {
      basculerFavori(fav.dataset.fav);
      return;
    }
    const cible = ev.target.closest(".anneau[data-s], .nom[data-s], .courbe[data-s]");
    if (cible && !ev.target.closest(".carte-kpi")) ouvrirFiche(cible.dataset.s);
  });
  // recherche des favoris : resultats a la frappe ; Entree suit la premiere action trouvee, Echap ferme
  $("recherche").addEventListener("input", montrerResultats);
  $("recherche").addEventListener("focus", montrerResultats);
  $("recherche").addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      $("recherche").value = "";
      fermerResultats();
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      const premier = $("resultats").querySelector(".resultat[data-ajout]");
      if (premier) {
        basculerFavori(premier.dataset.ajout);
        montrerResultats();
      }
    }
  });
  // courbe de la fiche : la souris, ou le doigt glisse dessus, montre la hausse a chaque date
  $("fiche").addEventListener("pointermove", survolCours);
  $("fiche").addEventListener("pointerdown", survolCours);
  $("fiche").addEventListener("pointerleave", finSurvolCours);
  $("fiche").addEventListener("close", () => {
    etat.fiche = null;
    etat.graphe = null;
  });
  let attente = null;                                 // telephone tourne, fenetre redimensionnee : courbe redessinee
  window.addEventListener("resize", () => {
    clearTimeout(attente);
    attente = setTimeout(() => {
      const l = etat.fiche && etat.palmares && etat.palmares.lignes.find((x) => x.s === etat.fiche);
      if (l) dessinerCours(l);
    }, 150);
  });
  document.addEventListener("mousemove", (ev) => {
    const svg = ev.target.closest && ev.target.closest(".courbe[data-s]");
    const cible = !svg && ev.target.closest && ev.target.closest("[data-bulle]");
    document.querySelectorAll(".courbe .point-survol[visibility=visible]").forEach((c) => {
      if (!svg || !svg.contains(c)) c.setAttribute("visibility", "hidden");
    });
    if (svg) survolCourbe(svg, ev);
    else if (cible) montrerBulle(cible.dataset.bulle, ev.clientX, ev.clientY);
    else cacherBulle();
  });
  // fenetres : bouton fermer, clic sur le fond
  for (const id of ["fiche", "methode"]) {
    const dlg = $(id);
    dlg.addEventListener("click", (ev) => {
      if (ev.target === dlg || ev.target.closest("[data-fermer]")) dlg.close();
    });
  }
  $("theme").addEventListener("click", () => {
    const sombre = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === "dark"
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.dataset.theme = sombre ? "light" : "dark";
    try { localStorage.setItem("pea-theme", document.documentElement.dataset.theme); } catch { /* facultatif */ }
  });
}

async function demarrer() {
  try {
    const t = localStorage.getItem("pea-theme");
    if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  } catch { /* facultatif */ }
  lirePreferences();
  lireFavoris();
  brancher();
  afficherOnglet(etat.filtres.onglet);
  squelettes();
  if (STATIQUE) {
    $("bouton-maj").querySelector(".libelle").textContent = "Actualiser";
    $("bouton-maj").title = "Relire les dernières données publiées par le PC";
    surveillerMisesAJour();
    try {
      await preparerChiffrement();
    } catch (err) {
      $("sous-titre").textContent = "Données indisponibles : " + err.message;
      return;
    }
  }
  if (await chargerPalmares()) {
    await toutAfficher();
  } else {
    afficherEntete();
    for (const id of ["liste-perf", "liste-div", "liste-veille", "liste-favoris"]) $(id).innerHTML = "";
    $("vitrine").innerHTML = "";
  }
  lireEtat();
}

demarrer();

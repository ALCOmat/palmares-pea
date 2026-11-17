"use strict";
/* Service worker du site publie (GitHub Pages) : l'app s'ouvre hors connexion avec les dernieres
   donnees recues. Page, styles et icones : copie en cache, rafraichie en arriere-plan. Donnees
   (donnees/*) : reseau d'abord, cache si le reseau manque.
   Nouvelle version : pea.publier change le nom du cache, donc ce fichier ; le navigateur installe ce
   nouveau service worker, qui prend la main tout de suite (skipWaiting, clients.claim) et la page se
   recharge (app.js, controllerchange). Les copies sont demandees au serveur, jamais au cache HTTP du
   navigateur (GitHub Pages les y garde 10 minutes). */
const CACHE = "palmares-pea-9d2cb8fa36-2026-11-17T09:46:36+01:00";
const COQUILLE = ["./", "index.html", "app.js", "style.css", "manifest.webmanifest", "icone-180.png", "icone-192.png",
  "icone-512.png", "icone-32.png"];

self.addEventListener("install", (ev) => {
  ev.waitUntil(caches.open(CACHE)
    .then((c) => c.addAll(COQUILLE.map((u) => new Request(u, { cache: "reload" }))))
    .then(() => self.skipWaiting()));
});

self.addEventListener("activate", (ev) => {
  ev.waitUntil(caches.keys()
    .then((cles) => Promise.all(cles.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

async function reseauDabord(requete) {
  const cache = await caches.open(CACHE);
  try {
    const reponse = await fetch(requete, { cache: "no-store" });
    if (reponse.ok) cache.put(requete, reponse.clone());
    return reponse;
  } catch (err) {
    const copie = await cache.match(requete);
    if (copie) return copie;
    throw err;
  }
}

async function cacheDabord(requete) {
  const cache = await caches.open(CACHE);
  const copie = await cache.match(requete);
  const frais = fetch(requete, { cache: "no-cache" }).then((r) => { if (r.ok) cache.put(requete, r.clone()); return r; })
    .catch(() => copie);
  return copie || frais;
}

self.addEventListener("fetch", (ev) => {
  const url = new URL(ev.request.url);
  if (ev.request.method !== "GET" || url.origin !== self.location.origin) return;
  ev.respondWith(url.pathname.includes("/donnees/") ? reseauDabord(ev.request) : cacheDabord(ev.request));
});

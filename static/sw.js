// Service worker. Two jobs:
// 1. Makes the app installable.
// 2. Receives shares (POST /share-target): an image is kept in a temporary
//    on-device cache for the page to read, then deleted. Text/links go to the
//    page in the URL. Nothing is sent to our server.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(clients.claim()));

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method === "POST" && url.pathname === "/share-target") {
    e.respondWith((async () => {
      try {
        const form = await e.request.formData();
        const file = form.get("image");
        if (file && file.size) {
          const cache = await caches.open("shared");
          await cache.put("/shared-image", new Response(file, { headers: { "Content-Type": file.type || "image/png" } }));
          return Response.redirect("/?shared=image", 303);
        }
        const text = [form.get("title"), form.get("text"), form.get("url")].filter(Boolean).join(" ");
        return Response.redirect("/?text=" + encodeURIComponent(text.slice(0, 5000)), 303);
      } catch (err) {
        return Response.redirect("/", 303);
      }
    })());
    return;
  }
  e.respondWith(fetch(e.request));
});

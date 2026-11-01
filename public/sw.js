const C='sb-v2',F=['/','/index.html','/manifest.webmanifest','/icon.svg','/icon-192.png'];
self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open(C).then(c=>c.addAll(F)))});
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim())));
// Open instantly from the saved copy, even while the server is asleep, and refresh the copy in the background.
// The API is never cached here.
self.addEventListener('fetch',e=>{const u=new URL(e.request.url);if(e.request.method!=='GET'||u.pathname.startsWith('/api'))return;
  e.respondWith(caches.match(e.request).then(m=>{
    const net=fetch(e.request).then(r=>{if(r.ok){const c=r.clone();caches.open(C).then(x=>x.put(e.request,c))}return r}).catch(()=>m||caches.match('/'));
    return m||net}))});

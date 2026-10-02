export default {
    async fetch(req, env) {
        const h = {
            "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
            "Content-Type": "text/plain",
            "Cache-Control": "no-store",
        };
        if (req.method === "OPTIONS") return new Response(null, { headers: h });
        if (new URL(req.url).pathname !== "/hit") return new Response("nope", { status: 404 });

        const ip = req.headers.get("CF-Connecting-IP") ?? "";
        const ua = req.headers.get("User-Agent") ?? "";
        const buf = await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(env.SALT + ip + ua)
        );
        const hash = [...new Uint8Array(buf)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

        await env.DB.prepare("INSERT OR IGNORE INTO seen(hash) VALUES (?)").bind(hash).run();
        const { n } = await env.DB.prepare("SELECT COUNT(*) AS n FROM seen").first();
        // Add offset from the old counter
        return new Response(String(n + Number(env.BASE ?? 0)), { headers: h });
    },
};

import cds from '@sap/cds';
import QRCode from 'qrcode';

const { SELECT } = cds.ql;

/**
 * DAYPASS bootstrap extras: the public QR landing resolver, the QR image
 * endpoint, the hash resolver, and a public JSON verification endpoint.
 * Registered on the Express app before CAP's services.
 *
 * Flow: a battery's QR encodes `<host>/p/<passportId>`. Scanning it hits the
 * resolver, which picks a tier from the caller's auth (none -> consumer) and
 * redirects into the viewer app at that tier's route.
 */
cds.on('bootstrap', (app: any) => {
    // --- Tier resolver: GET /p/:passportId -----------------------------------
    app.get('/p/:passportId', (req: any, res: any) => {
        const passportId = String(req.params.passportId || '');
        const tier = tierFromAuth(req.headers.authorization);
        const hash = tier === 'consumer' ? '' : `#/${tier}`;
        res.redirect(302, `/passport/webapp/index.html?p=${encodeURIComponent(passportId)}${hash}`);
    });

    // --- QR image: GET /qr/:passportId.png -----------------------------------
    app.get('/qr/:file', async (req: any, res: any) => {
        const passportId = String(req.params.file || '').replace(/\.png$/i, '');
        if (!passportId) return res.status(400).end();
        const host = `${req.protocol}://${req.get('host')}`;
        try {
            const png = await QRCode.toBuffer(`${host}/p/${passportId}`, { width: 320, margin: 1 });
            res.type('image/png');
            res.setHeader('Cache-Control', 'public, max-age=3600');
            res.end(png);
        } catch (e: any) {
            res.status(500).end(String(e?.message ?? e));
        }
    });

    // --- Supplier resolve by anchored hash: GET /resolve/:payloadHash --------
    app.get('/resolve/:payloadHash', async (req: any, res: any) => {
        const payloadHash = String(req.params.payloadHash || '').replace(/^0x/, '').toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(payloadHash)) return res.status(400).end('invalid payloadHash');
        try {
            const row: any = await SELECT.one.from('passport.Passports').columns('passportId').where({ payloadHash });
            if (!row) return res.status(404).end('no battery for that payloadHash');
            const tier = tierFromAuth(req.headers.authorization);
            const hash = tier === 'consumer' ? '' : `#/${tier}`;
            return res.redirect(302, `/passport/webapp/index.html?p=${encodeURIComponent(row.passportId)}${hash}`);
        } catch (e: any) {
            return res.status(500).end(String(e?.message ?? e));
        }
    });

    // --- Public verification JSON: GET /verify/:passportId --------------------
    // Loopback HTTP call into the producer action: an in-process send would
    // nest the plugin's on-chain lookups (which index/write) inside one shared
    // transaction — the known "Build not found"/deadlock class. The HTTP hop
    // gives each action the request isolation it was built for. Demo-auth only;
    // a production deployment fronts this differently (or drops the route).
    app.get('/verify/:passportId', async (req: any, res: any) => {
        const passportId = String(req.params.passportId || '');
        if (!passportId) return res.status(400).end();
        try {
            const port = req.socket?.localPort ?? 4004;
            const upstream = await fetch(`http://127.0.0.1:${port}/api/v1/producer/verifyPassportOnChain`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: 'Basic ' + Buffer.from('producer:producer').toString('base64')
                },
                body: JSON.stringify({ passportId })
            });
            const result: any = await upstream.json().catch(() => ({}));
            if (!upstream.ok) {
                const msg = String(result?.error?.message ?? `HTTP ${upstream.status}`);
                return res.status(upstream.status === 404 ? 404 : 500).json({ passportId, verified: false, error: msg });
            }
            const checks = JSON.parse(result.checksJson ?? '[]');
            res.json({ passportId, verified: result.verified === true, checks });
        } catch (e: any) {
            res.status(500).json({ passportId, verified: false, error: String(e?.message ?? e) });
        }
    });
});

/**
 * Map an HTTP Basic auth header to a viewer tier for the redirect. The mocked
 * users are named after their role. Partner DIDs land on the consumer route;
 * their per-passport grants are enforced by the API regardless of route.
 */
function tierFromAuth(authHeader?: string): 'consumer' | 'recycler' | 'authority' {
    if (!authHeader || !authHeader.toLowerCase().startsWith('basic ')) return 'consumer';
    try {
        const decoded = Buffer.from(authHeader.slice(6).trim(), 'base64').toString('utf8');
        const user = decoded.split(':')[0];
        if (user === 'authority') return 'authority';
        if (user === 'recycler') return 'recycler';
    } catch { /* fall through */ }
    return 'consumer';
}

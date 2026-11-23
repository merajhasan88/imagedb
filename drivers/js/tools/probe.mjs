// The driver's probe: node tools/probe.mjs SOCKET PASSWORD SQL
// Connects over the server's Unix-domain socket as the role admin, runs the one statement, prints its columns, its rows
// (one a line, JSON with bigints as their digits) and its status, then exits 0; on any error prints the driver's error
// (its class, code and words) and exits 1. Needs dist/ (tsc -p tsconfig.json, or run_tests.sh).
import drv from '../dist/src/index.js';

const [socket, password, sql] = process.argv.slice(2);
if (!socket || password === undefined || !sql) {
    console.error('usage: node tools/probe.mjs SOCKET PASSWORD SQL');
    process.exit(2);
}
const show = (v) => JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? x.toString() : Buffer.isBuffer(x) ? '\\x' + x.toString('hex') : x));
let c = null;
try {
    c = await drv.connect({ socket }, { user: 'admin', password });
    const r = await c.query(sql);
    if (r.columns) {
        console.log(r.columns.map((x) => x.name + ' ' + x.type).join(' | '));
        for (const row of r.rows) console.log(show(row.map((v) => (v !== null && typeof v === 'object' && !Buffer.isBuffer(v) ? String(v) : v))));
    }
    if (r.copyOut) process.stdout.write(r.copyOut);
    console.log('(' + (r.status || r.rows.length + (r.rows.length === 1 ? ' row' : ' rows')) + ')');
    await c.close();
    process.exit(0);
} catch (e) {
    console.log('error: ' + (e && e.name ? e.name : 'Error') + (e && e.code !== undefined ? ' ' + e.code + (e.codeName ? ' ' + e.codeName : '') : '') +
        ': ' + (e && e.message ? e.message : String(e)));
    if (c) c.destroy();
    process.exit(1);
}

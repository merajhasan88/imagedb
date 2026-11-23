/* Phase 2 of run_tests.sh: server A restarted after `imagedb-server cert SDIR --renew` (the same key signed again by the
 * same CA): the pin taken before the renewal, and the CA file, still verify it; the socket path reused */
import { test } from 'node:test';
import assert = require('node:assert');
import { connect } from '../src/index';

function env(k: string): string {
    const v = process.env[k];
    if (!v) throw new Error('run by run_tests.sh: ' + k + ' is not set');
    return v;
}
const cred = { user: env('IMDB_JS_USER'), password: env('IMDB_JS_PASSWORD') };

test('after cert --renew: the old pin, the CA, the socket', { timeout: 60000 }, async () => {
    const port = +env('IMDB_JS_PORT_A');
    for (const o of [{ pin: env('IMDB_JS_PIN_A') }, { caFile: env('IMDB_JS_CA_A') }]) {
        const c = await connect({ host: '127.0.0.1', port, ...o }, cred);
        try {
            assert.deepStrictEqual((await c.query('SELECT COUNT(*) FROM s1')).rows, [[1n]]); /* phase 1's table: the same database */
            await c.close();
        } finally {
            c.destroy();
        }
    }
    const s = await connect({ socket: env('IMDB_JS_SOCK_A') }, cred);
    try {
        await s.ping();
        await s.close();
    } finally {
        s.destroy();
    }
});

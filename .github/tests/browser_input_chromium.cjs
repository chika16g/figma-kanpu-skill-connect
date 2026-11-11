// Run with Node and a local Playwright install. No course site or credential store is used.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { resolve } = require('node:path');
const { createInterface } = require('node:readline');
const { test } = require('node:test');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const source = resolve(__dirname, '../../connect.py');
const fixture = `
import runpy
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

main = runpy.run_path(sys.argv[1])['main']
calls = []

def exchange(origin, code, store, api):
    assert code == 'a' * 64 + '.' + 'b' * 64
    calls.append('exchange')
    return {'status': 'paired'}

def install(*args, **kwargs):
    assert calls == ['exchange']
    calls.append('install')
    return {'status': 'installed'}

# Only the downstream credential store and remote calls are simulated.
modules = {
    'update_client': SimpleNamespace(NAME='figma-kanpu-totonoe'),
    'authenticated_delivery': SimpleNamespace(origin_url=lambda origin: origin,
        configure_credential_store=lambda store: None, install=install),
    'credential_store': SimpleNamespace(
        MacOSKeychainStore=lambda *, approved: object(),
        WindowsCredentialStore=lambda *, approved: object(),
    ),
    'pair_client': SimpleNamespace(exchange=exchange, clear_pending_after_install=lambda *args: True),
}
main.__globals__['load'] = modules.__getitem__
with TemporaryDirectory() as directory:
    backend = '--use-windows-credential-manager' if sys.platform == 'win32' else '--use-macos-keychain'
    sys.argv = [sys.argv[1], '--origin', 'https://course.example.invalid', '--destination',
        str(Path(directory) / 'skill'), '--accept-source', '--endpoint-profile',
        'wordpress_self_registration_v1', backend, '--pair', '--browser-input']
    assert main()['status'] == 'installed'
    assert calls == ['exchange', 'install']
`;

test('Chromium sends the exact loopback Origin on native form submission', { timeout: 20000 }, async () => {
    const browser = await chromium.launch({
        executablePath: process.env.CHROMIUM_EXECUTABLE,
        args: ['--no-proxy-server'],
    });
    const listener = spawn(process.env.PYTHON || 'python3', ['-B', '-u', '-c', fixture, source], {
        env: { ...process.env, PYTHONIOENCODING: 'ascii' },
    });
    const exited = once(listener, 'exit');
    const lines = createInterface({ input: listener.stdout });
    try {
        const announcement = await lines[Symbol.asyncIterator]().next();
        assert.equal(announcement.done, false, 'loopback listener did not announce its URL');
        const { status, url, message } = JSON.parse(announcement.value);
        assert.equal(status, 'input_required');
        assert.match(message, /非表示入力欄/);
        const page = await browser.newPage();
        const inputPage = await page.goto(url);
        assert.equal(inputPage.status(), 200);
        await page.getByLabel('初回接続コード', { exact: true }).fill('a'.repeat(64) + '.' + 'b'.repeat(64));
        const [response] = await Promise.all([
            page.waitForResponse(response => response.request().method() === 'POST'),
            page.getByRole('button', { name: '接続を進める' }).click(),
        ]);
        const origin = await response.request().headerValue('origin');
        const policy = await inputPage.headerValue('referrer-policy');
        console.log(`Chromium ${browser.version()} / Referrer-Policy: ${policy} / Origin: ${origin === new URL(url).origin ? 'exact loopback match' : origin} / POST: ${response.status()}`);
        assert.equal(response.url(), new URL('/pair', url).href);
        assert.equal(origin, new URL(url).origin);
        assert.equal(response.status(), 200);
        await page.getByText('入力を受け取りました。', { exact: false }).waitFor();
        const [code] = await exited;
        assert.equal(code, 0, 'the dummy code did not reach the simulated pairing and installation');
    } finally {
        lines.close();
        listener.kill();
        await browser.close();
    }
});

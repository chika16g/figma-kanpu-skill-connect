'use strict';

// Launch the installed Chrome with an isolated profile. The only form value is a fixture.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { existsSync } = require('node:fs');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: wait } = require('node:timers/promises');

async function poll(read, label) {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
        const value = await read();
        if (value) return value;
        await wait(50);
    }
    throw new Error(label);
}

async function test(url) {
    assert.match(url, /^http:\/\/127\.0\.0\.1:[0-9]+\/$/);
    const windows = [process.env.ProgramFiles, process.env['ProgramFiles(x86)']]
        .filter(Boolean).map(folder => path.join(folder, 'Google', 'Chrome', 'Application', 'chrome.exe'));
    const binary = process.env.CHROMIUM_EXECUTABLE || windows.find(existsSync);
    assert.ok(binary, 'Chrome executable not found');
    const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'course-chrome-smoke-'));
    const chrome = spawn(binary, [
        '--headless', '--no-first-run', '--disable-background-networking', '--no-proxy-server',
        '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1',
        '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
        '--user-data-dir=' + profile, 'about:blank',
    ], { stdio: 'ignore', windowsHide: true });
    let socket;
    const exited = new Promise(resolve => {
        chrome.once('error', resolve);
        chrome.once('exit', resolve);
    });
    try {
        const port = await poll(async () => {
            if (!chrome.pid || chrome.exitCode !== null) throw new Error('Chrome failed to start');
            try {
                const state = await fs.readFile(path.join(profile, 'DevToolsActivePort'), 'utf8');
                const number = state.split(/\r?\n/, 1)[0];
                return /^\d+$/.test(number) ? number : null;
            } catch (error) {
                if (error.code === 'ENOENT') return null;
                throw error;
            }
        }, 'Chrome did not start DevTools');
        const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`, {
            signal: AbortSignal.timeout(3000),
        })).json();
        const target = pages.find(entry => entry.type === 'page');
        assert.ok(target && target.webSocketDebuggerUrl.startsWith(`ws://127.0.0.1:${port}/`));
        socket = new WebSocket(target.webSocketDebuggerUrl);
        await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('DevTools connection timed out')), 3000);
            socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
            socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('DevTools error')); }, { once: true });
        });
        const callbacks = new Map();
        let sequence = 0;
        socket.addEventListener('message', ({ data }) => {
            const response = JSON.parse(data);
            callbacks.get(response.id)?.(response);
        });
        function command(method, params = {}) {
            const id = ++sequence;
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => {
                    callbacks.delete(id);
                    reject(new Error('DevTools timeout: ' + method));
                }, 3000);
                callbacks.set(id, response => {
                    clearTimeout(timer);
                    callbacks.delete(id);
                    if (response.error) reject(new Error('DevTools error: ' + method));
                    else resolve(response.result);
                });
                socket.send(JSON.stringify({ id, method, params }));
            });
        }
        async function evaluate(expression) {
            const result = await command('Runtime.evaluate', { expression, returnByValue: true });
            assert.ok(!result.exceptionDetails, 'Browser expression failed');
            return result.result.value;
        }
        const navigation = await command('Page.navigate', { url });
        assert.ok(!navigation.errorText, navigation.errorText);
        await poll(() => evaluate("!!document.querySelector('input[type=password][name=code]')"), 'Password field did not load');
        const submitted = await evaluate(`(() => {
            const field = document.querySelector('input[type=password][name=code]');
            field.value = 'a'.repeat(64) + '.' + 'b'.repeat(64);
            field.form.requestSubmit();
            return true;
        })()`);
        assert.ok(submitted);
        await poll(() => evaluate("location.pathname === '/pair' && document.title === '入力を受け取りました'"),
            'The loopback server did not accept the browser form');
        console.log(JSON.stringify({ status: 'PASS', real_chrome_form_submit: true }));
    } finally {
        if (socket) socket.close();
        chrome.kill();
        await Promise.race([exited, wait(3000)]);
        await fs.rm(profile, { recursive: true, force: true, maxRetries: 4, retryDelay: 100 });
    }
}

test(process.argv[2]).catch(error => {
    console.error(error.message);
    process.exitCode = 1;
});

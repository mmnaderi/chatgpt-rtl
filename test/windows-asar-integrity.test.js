import assert from 'node:assert/strict';
import test from 'node:test';
import { NtExecutable, NtExecutableResource } from 'resedit';
import { updateWindowsAsarIntegrity } from '../bin/windows-asar-integrity.js';

const originalHash = 'a'.repeat(64);
const patchedHash = 'b'.repeat(64);

function executableWithIntegrity() {
    const exe = NtExecutable.createEmpty(true, false);
    const resources = NtExecutableResource.from(exe);
    const records = [
        { file: 'resources\\app.asar', alg: 'SHA256', value: originalHash },
        { file: 'resources\\other.asar', alg: 'SHA256', value: originalHash }
    ];
    resources.entries.push({
        type: 'INTEGRITY',
        id: 'ELECTRONASAR',
        lang: 1033,
        codepage: 0,
        bin: new TextEncoder().encode(JSON.stringify(records)).buffer
    });
    resources.outputResource(exe);
    return exe.generate();
}

test('updates only the app.asar integrity entry in the Windows launcher', () => {
    const result = updateWindowsAsarIntegrity(executableWithIntegrity(), originalHash, patchedHash);
    const resources = NtExecutableResource.from(NtExecutable.from(result));
    const [app, other] = JSON.parse(new TextDecoder().decode(resources.entries[0].bin));
    assert.equal(app.value, patchedHash);
    assert.equal(other.value, originalHash);
});

test('rejects a Windows launcher paired with the wrong original archive', () => {
    assert.throws(
        () => updateWindowsAsarIntegrity(executableWithIntegrity(), patchedHash, originalHash),
        /does not match the original archive/
    );
});

test('leaves a Windows launcher without an ASAR integrity resource untouched', () => {
    assert.equal(
        updateWindowsAsarIntegrity(NtExecutable.createEmpty(true, false).generate(), originalHash, patchedHash),
        null
    );
});

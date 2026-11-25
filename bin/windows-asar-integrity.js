import { NtExecutable, NtExecutableResource } from 'resedit';

export function updateWindowsAsarIntegrity(executableBytes, originalHash, patchedHash) {
    const executable = NtExecutable.from(executableBytes, { ignoreCert: true });
    const resources = NtExecutableResource.from(executable);
    const entries = resources.entries.filter(entry =>
        String(entry.type).toUpperCase() === 'INTEGRITY' &&
        String(entry.id).toUpperCase() === 'ELECTRONASAR'
    );
    if (!entries.length) return null;

    for (const entry of entries) {
        const records = JSON.parse(Buffer.from(entry.bin).toString('utf8'));
        const archive = records.find(record =>
            record.file.replaceAll('\\', '/').toLowerCase() === 'resources/app.asar'
        );
        if (archive?.alg !== 'SHA256' || archive.value !== originalHash) {
            throw new Error('Windows executable ASAR integrity does not match the original archive.');
        }
        archive.value = patchedHash;
        const bytes = Uint8Array.from(Buffer.from(JSON.stringify(records)));
        entry.bin = bytes.buffer;
    }
    resources.outputResource(executable);
    return Buffer.from(executable.generate());
}

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mintPolicyCompiledCode, mintPolicyParamsJson, mintRequiredSignersJson } from '../../srv/lib/mint-policy';

const PKH = 'fa86ab6c36d5d32994cb6df00d40956386f6e7003e816a435aa9db88';

describe('mint-policy artifact', () => {
    it('loads the committed blueprint compiledCode', () => {
        const code = mintPolicyCompiledCode();
        assert.match(code, /^[0-9a-f]+$/i);
        assert.ok(code.length > 100, 'compiledCode suspiciously short');
        assert.equal(mintPolicyCompiledCode(), code); // memoized
    });

    it('produces the pinned scriptParamsJson encoding', () => {
        assert.deepEqual(JSON.parse(mintPolicyParamsJson(PKH)), [
            { uplc: 'data', value: { bytes: PKH } }
        ]);
        assert.deepEqual(JSON.parse(mintRequiredSignersJson(PKH.toUpperCase())), [PKH]);
    });

    it('rejects malformed key hashes', () => {
        assert.throws(() => mintPolicyParamsJson('ab'), /28 bytes hex/);
        assert.throws(() => mintRequiredSignersJson('zz'.repeat(28)), /28 bytes hex/);
    });
});

const jsonld = require('jsonld');
const { KeyPairOptions } = require('crypto-ld');

const jsigs = require('jsonld-signatures');
const { Ed25519KeyPair, SECURITY_CONTEXT_URL, SECURITY_CONTEXT_V2_URL, suites } = jsigs;
const { Ed25519Signature2018 } = suites;

const ocapld = require('ocapld');
const { CapabilityInvocation, CapabilityDelegation, Caveat, ExpirationCaveat } = ocapld;

const alice = {
    "@context": "https://w3id.org/security/v2",
    "id": "https://example.com/i/alice",
    "publicKey": [
        {
            "@context": "https://w3id.org/security/v2",
            "id": "https://example.com/i/alice/keys/1",
            "type": "Ed25519VerificationKey2018",
            "controller": "https://example.com/i/alice",
            "publicKeyBase58": "GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq",
            "privateKeyBase58": "3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvMJKk6QErH3wgdHp8itkSSiF"
        }
    ],
    "capabilityInvocation": ["https://example.com/i/alice/keys/1"],
    "capabilityDelegation": ["https://example.com/i/alice/keys/1"]
};
const bob = {
    "@context": "https://w3id.org/security/v2",
    "id": "https://example.com/i/bob",
    "capabilityInvocation": [
        {
            "id": "https://example.com/i/bob/keys/1",
            "type": "Ed25519VerificationKey2018",
            "controller": "https://example.com/i/bob",
            "publicKeyBase58": "CXbgG2vPnd8FWLAZHoLRn3s7PRwehWsoMu6v1HhN9brA",
            "privateKeyBase58": "3LftyxxRPxMFXwVChk14HDybE2VnBnPWaLX31WreZwc8V8xCCuoGL7dcyxnwkFXa8D7CZBwAGWj54yqoaxa7gUne"
        }
    ],
    "capabilityDelegation": [
        {
            "id": "https://example.com/i/bob/keys/2",
            "type": "Ed25519VerificationKey2018",
            "controller": "https://example.com/i/bob",
            "publicKeyBase58": "CXbgG2vPnd8FWLAZHoLRn3s7PRwehWsoMu6v1HhN9brA",
            "privateKeyBase58": "3LftyxxRPxMFXwVChk14HDybE2VnBnPWaLX31WreZwc8V8xCCuoGL7dcyxnwkFXa8D7CZBwAGWj54yqoaxa7gUne"
        }
    ]
};
const loaderData = {
    'https://example.com/i/alice': alice,
    'https://example.com/i/alice/keys/1': alice['publicKey'][0],
    'https://example.org/alice/caps#1': {
        '@context': 'https://w3id.org/security/v2',
        id: 'https://example.org/alice/caps#1',
        invoker: 'https://example.com/i/alice/keys/1',
        delegator: 'https://example.com/i/alice/keys/1'
    },
    'https://example.com/i/bob': bob,
    'https://example.com/i/bob/keys/1': {
        '@context': 'https://w3id.org/security/v2',
        "id": "https://example.com/i/bob/keys/1",
        "type": "Ed25519VerificationKey2018",
        "controller": "https://example.com/i/bob",
        "publicKeyBase58": "CXbgG2vPnd8FWLAZHoLRn3s7PRwehWsoMu6v1HhN9brA",
        "privateKeyBase58": "3LftyxxRPxMFXwVChk14HDybE2VnBnPWaLX31WreZwc8V8xCCuoGL7dcyxnwkFXa8D7CZBwAGWj54yqoaxa7gUne"
    },
    "https://schema.bitmark.com/git/v1": {
        "@context": {
            "branchRegExp": "https://schema.bitmark.com/git/branchRegExp"
        }
    }
}
const testLoader = async url => {
    return {
        contextUrl: null,
        document: loaderData[url],
        documentUrl: url
    };
}

class BranchCaveat extends Caveat {
    /**
     * @param [branch] {string} the current branch to use to
     *   validate an branch caveat.
     * @param [branchRegExp] {string} the regular expression of acceptable branched to
     *   attach to a capability as a caveat.
     */
    constructor({ branch, branchRegExp } = {}) {
        // super({ type: 'https://schema.bitmark.com/git/branchCaveat' });
        super({ type: 'git:branchCaveat' });
        if (branch !== undefined) {
            this.branch = branch;
        }
        if (branchRegExp !== undefined) {
            this.branchRegExp = branchRegExp;
        }
    }

    /**
     * Determines if this caveat has been met.
     *
     * @param caveat {object} the caveat parameters.
     * @param options.capability {object} the full capability.
     *
     * @return {Promise<object>} resolves to can object with `valid` and `error`.
     */
    async validate(caveat) {
        try {
            const regex = RegExp(caveat['https://schema.bitmark.com/git/branchRegExp']);
            if (!regex.test(this.branch)) {
                throw new Error('The capability is not allowed to write to this branch:', this.branch);
            }
            return { valid: true };
        } catch (error) {
            return { valid: false, error };
        }
    }

    /**
     * Adds this caveat to the given capability.
     *
     * @param capability {object} the capability to add this caveat to.
     *
     * @return {Promise<object>} resolves to the capability.
     */
    async update(capability) {
        const branchRegExp = this.branchRegExp;
        jsonld.addValue(capability, 'caveat', {
            type: this.type,
            branchRegExp
        });
        return capability;
    }
};

(async function main() {
    // define the target (root capability)
    const rootCapability = {
        '@context': SECURITY_CONTEXT_V2_URL,
        id: 'https://example.org/alice/caps#1',
        invoker: 'https://example.com/i/alice/keys/1',
        delegator: 'https://example.com/i/alice/keys/1'
    };

    // mint a new capability with two caveats for bob
    const newCapability = {
        '@context': [
            SECURITY_CONTEXT_URL,
            'https://schema.bitmark.com/git/v1',
            { git: 'https://schema.bitmark.com/git/v1' },
        ],
        id: 'https://example.org/bob/caps/#1',
        parentCapability: rootCapability.id,
        invocationTarget: rootCapability.id,
        invoker: bob.id
    };
    const expires = new Date();
    expires.setHours(expires.getHours() + 1);
    new ExpirationCaveat({ expires }).update(newCapability);
    new BranchCaveat({ branchRegExp: 'feature*' }).update(newCapability);

    const delegatedCapability = await jsigs.sign(newCapability, {
        suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(alice['publicKey'][0]),
        }),
        purpose: new CapabilityDelegation({
            capabilityChain: [rootCapability.id],
        }),
        documentLoader: testLoader
    });
    loaderData[delegatedCapability['id']] = delegatedCapability;
    console.log('Bob acquires his capability:');
    console.log(delegatedCapability);

    // verify Alice's delegation
    result = await jsigs.verify(delegatedCapability, {
        suite: new Ed25519Signature2018(),
        purpose: new CapabilityDelegation({
            caveat: [new ExpirationCaveat({ expires }), new BranchCaveat({ branch: 'feature/login' })],
        }),
        documentLoader: testLoader
    });
    console.log('-> Whether Alice delegates Bob to operate the branch "feature/login"?', result.verified, '\n');

    // invoke the delegated capability
    const msg = {
        '@context': SECURITY_CONTEXT_V2_URL,
        id: 'urn:uuid:cab83279-c695-4e66-9458-4327de49197a',
        nonce: '123'
    };
    const invocation = await jsigs.sign(msg, {
        suite: new Ed25519Signature2018({
            key: new Ed25519KeyPair(bob['capabilityInvocation'][0])
        }),
        purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
        })
    });
    console.log('Bob invocates his capability:');
    console.log(invocation);

    // verify the invocation of bob's capability
    result = await jsigs.verify(invocation, {
        suite: new Ed25519Signature2018(),
        purpose: new CapabilityInvocation({
            expectedTarget: rootCapability.id,
            suite: new Ed25519Signature2018(),
            caveat: [new ExpirationCaveat(), new BranchCaveat({ branch: 'feature/login' })],
        }),
        documentLoader: testLoader
    });
    console.log('-> Whether Bob can push to branch "feature/login"?', result.verified);

    // reject the invocation of bob's capability if he tries to operate on the master branch
    result = await jsigs.verify(invocation, {
        suite: new Ed25519Signature2018(),
        purpose: new CapabilityInvocation({
            expectedTarget: rootCapability.id,
            suite: new Ed25519Signature2018(),
            caveat: [new ExpirationCaveat(), new BranchCaveat({ branch: 'master' })],
        }),
        documentLoader: testLoader
    });
    console.log('-> Whether Bob can push to branch "master"?', result.verified);
})();
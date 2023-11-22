* TAP: 20
* Title: Ephemeral signing keys for timestamp, snapshot and target roles using OpenPubkey
* Version: 0
* Last-Modified: 17/11/2023
* Author: James Carnegie
* Type: Standardization
* Status: Draft
* Content-Type: markdown
* Created: 02/11/2023
* TUF-Version:

# Abstract

In order to achieve end-to-end software update security, TUF requires the signing metadata about updates with private key. However, this has proven challenging for some implementers to create, store, and secure these private keys in order to ensure they remain private. This TAP proposes adding a new signing option using [OpenPubkey](https://github.com/openpubkey) to simplify key management by allowing online roles to use OIDC providers to bind ephemeral signing keys to their identities instead of using self-managed private keys, and these identities (and the corresponding OpenPubkey certificates) are used for signature verification.

# Motivation

Key management has been a major concern for TUF adoption. Under a typical deployment, the root role must be signed by some threshold of offline keys. Similarly, keys of Targets roles are often held offline by developers and used to sign release metadata. Snapshot role keys are sometimes held online, and Timestamp roles keys are mostly held online so that automated processes (such as GitHub Actions) are able to sign metadata without human interaction.

Online keys are often kept in some kind of Key Management Service against which the signing processes must authenticate in order to call the signing operation. In other cases, signing keys are stored in the CI system itself (e.g. GitHub Action's Secrets). These approaches but require the setup, monitoring and maintenance of secrets, and are a barrier to TUF adoption because even in medium sized organisations many different teams must be coordinated to achieve the necessary access and approvals. They also introduce additional attack vectors on the storage and access of the keys.

Moreover, as discussed in detail in [TAP-18: Ephemeral identity verification using sigstore's Fulcio for TUF developer key management](tap18.md), developers struggle to manage their own keys securely for signing TUF targets' metadata. Similarly, this TAP also proposes that developers should be able to sign TUF target metadata using ephemeral signing keys based on their OIDC identities, but using OpenPubkey instead of Sigstore's Fulcio.

When signing TUF metadata, it's obviously important that the signatures be verifiable for a significant time into the future. This presents a problem when using OpenPubkey because signature verification requires access to the OIDC provider's public key that was used to sign the ID token that is part of the OpenPubkey signing certificate (OPK). As per the [OIDC spec](https://openid.net/developers/specs/), the current and previous OIDC keys are available at a well known location, for example [GitHub Actions OIDC JWKS URI](https://token.actions.githubusercontent.com/.well-known/jwks). However, these keys are rotated at unpredictable frequencies at the whim of the provider. So unless there is a trusted source of historical OIDC provider public keys, signatures created against prior (now rotated or revoked) public keys will become unverifiable.

It's worth noting that currently there is no way to attribute an expired OIDC public key to the OIDC provider.

This TAP proposes both a mechanism for signing TUF metadata with OpenPubkey and keeping a log of historical OIDC public keys so that metadata signed under those keys can be verified after key rotation.

# Specification

This TAP modifies the Timestamp role to support logging of OIDC public keys as they change and introduces a new `keytype` so that the root role can specify the keys as well as OPK claims that must be present in other roles' signatures.

## Initial Configuration

The root role signs the policy for the other roles that are signed by OpenPubkey. A new `keytype`: `opk` is introduced using the `jws` scheme (FIX this - it's not really jws, but the signatures will be).

`keyval` contains at least two public keys from each OIDC provider at the time of root signing in the `public` field, as well as a map of ID token claims in the `claims` field. When an OpenPubkey signature is verified, the OIDC public key is first used to verify the signature, then the claims in the ID token are checked against the claims specified in `claims`.

### root.json
```json
{
  "signatures": [
    {
      "keyid": "cb3fbd83df4ba2471a736b065650878280964a98843ec13b457a99b2a21cc3b4",
      "sig": "a312b9c3cb4a1b693e8ebac5ee1ca9cc01f2661c14391917dcb111517f72370809
              f32c890c6b801e30158ac4efe0d4d87317223077784c7a378834249d048306"
    }
  ],
  "signed": {
    "_type": "root",
    "spec_version": "1.0.0",
    "consistent_snapshot": false,
    "expires": "2030-01-01T00:00:00Z",
    "keys": {
      "1bf1c6e3cdd3d3a8420b19199e27511999850f4b376c4547b2f32fba7e80fca3": {
        "keytype": "opk",
        "scheme": "jws",
        "keyval": {
          "claims": {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": "repo:theupdateframework/gha-test:ref:refs/heads/main",
          },
          "public" : {
              "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs": {
                "iss": "https://token.actions.githubusercontent.com",
                "nbf": 1698760418,
                "exp": null,
                "sts": "valid",
                "jwk": {
                      "n": "... <modulus> ...",
                      "kty": "RSA",
                      "kid": "1F2AB83404C08EC9EA0BB99DAED02186B091DBF4",
                      "alg": "RS256",
                      "e": "AQAB",
                      "use": "sig",
                      "x5c": ["... <x509 cert chain> ..."],
                      "x5t": "Hyq4NATAjsnqC7mdrtAhhrCR2_Q"
                    }
              },
              "OzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xt": {
                  "iss": "https://token.actions.githubusercontent.com",
                  "nbf": 1698760417,
                  "exp": null,
                  "sts": "valid",
                  "jwk": {
                        "n": "... <modulus> ...",
                        "kty": "RSA",
                        "kid": "2F2AB83404C08EC9EA0BB99DAED02186B091DBF5",
                        "alg": "RS256",
                        "e": "AQAB",
                        "use": "sig",
                        "x5c": ["... <x509 cert chain> ..."],
                        "x5t": "Iyq4NATAjsnqC7mdrtAhhrCR2_L"
                  }
              }
            }
          }
      },

      "cb3fbd83df4ba2471a736b065650878280964a98843ec13b457a99b2a21cc3b4": {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": {
          "public": "66dd78c5c2a78abc6fc6b267ff1a8017ba0e8bfc853dd97af351949bba021275"
        }
      },
    },
    "roles": {
      "root": {
        "keyids": [
          "cb3fbd83df4ba2471a736b065650878280964a98843ec13b457a99b2a21cc3b4"
        ],
        "threshold": 1
      },
      "snapshot": {
        "keyids": [
          "1bf1c6e3cdd3d3a8420b19199e27511999850f4b376c4547b2f32fba7e80fca3"
        ],
        "threshold": 1
      },
      "targets": {
        "keyids": [
          "1bf1c6e3cdd3d3a8420b19199e27511999850f4b376c4547b2f32fba7e80fca3"
        ],
        "threshold": 1
      },
      "timestamp": {
        "keyids": [
          "1bf1c6e3cdd3d3a8420b19199e27511999850f4b376c4547b2f32fba7e80fca3"
        ],
        "threshold": 1
      }
    },
    "version": 1
  }
}
```

**NB: `keyids` used in `root.json` are sha256 hashes of the canonical JSON form of `keyval` to keep them unique within the document and do not correspond to the `kid` field used in OIDC resources**

When OIDC providers' public keys are rotated, the old public keys in `root.json` can no longer be used to verify new signatures. Similarly, the new public keys cannot be used to verify signatures under the old public keys in `root.json`.

The Timestamp role is responsble for maintaining a log of OIDC OP public keys for all issuers of `opk` type keys in `root.json`. To keep the size of the timestamp.json metadata small, only one additional entry is added: `opkl.json`.

The timestamp role in this example is signing using OpenPubkey, but this isn't necessary in order to maintain the log for other roles; offline keys could also have been used.

`timestamp.json`

```json
{
  "signatures": [
    {
      "keyid": "1bf1c6e3cdd3d3a8420b19199e27511999850f4b376c4547b2f32fba7e80fca3",
      "sig": "...OPK..."
    }
  ],
  "signed": {
    "_type": "timestamp",
    "spec_version": "1.0.0",
    "expires": "2030-01-01T00:00:00Z",
    "meta": {
      "snapshot.json": {
        "hashes": {
          "sha256": "c14aeb4ac9f4a8fc0d83d12482b9197452f6adf3eb710e3b1e2b79e8d14cb681"
        },
        "length": 1007,
        "version": 1
      },
      "opkl.json": {
        "hashes": {
          "sha256": "4980db466497a606351072cf9afe551b1b236b2b0745316c3e3cbcf756040469"
        },
        "length": 6008,
        "version": 1
      }
    },
    "version": 1
  }
}

```

The `keyid` above is a reference to the corresponding `keyid` in `root.json`, but because OIDC public keys rotate, the actual public key used in the signature changes over time as the keys are rotated. Resolution of public keys and use of signatures is discussed below.

`opkl.son` contains a map of JWK thumbprints (calculated according to [RFC-7638](https://datatracker.ietf.org/doc/html/rfc7638)) to JWK metadata, including the `jwk` whose contents are as returned from the JWKS endpoint.

Until the first timestamp, the file is empty.

### Updating the OIDC OP key log

`opkl.json` is updated by the following process for each issuer in `root.json`:

* Initial State: root retrieves and stores all OP public keys (A, B) aka, the primordial set
* T1: timestamp role retrieves all OP public keys (A, B). Compares to those stored in `root.json` and fails if they don't match.  Requests an ID token from issuer, and determines which OP public key it is associated it (say B). Checks that it's in the primoridial set, and fails otherwise. Creates `opkl.json` containing both keys A and B (see below) including a signature (using GQ?) over A. Then `timestamp.json` is updated and signed.
* T2: timestamp role retrieves all OP public keys (B, C). Requests an ID token from issuer, and determines which OP public key it is associated it (say C). Verifies that B is in `opkl.json` and that B was used to sign A, and that A and B are in the primordial set, fails otherwise. Adds C to `opkl.json`, and signs B using the ID token. Then `timestamp.json` is updated and signed.
* TX: at each timestamp, the above process is repeated until a chain of signatures from a current/live OIDC OP key to the keys in `root.json` is found.

If at any point, an attacker attempts to add their own OP public key to `opkl.json`, presumably signing the previous legitimate OP public key as in the flow above, the timestamp role will fail to validate on the next run and clients, which follow the same process, will also fail.

Clearly there are some issues:

1. OIDC providers must have more than one JWK on the JWKS endpoint
2. JWK rotation should be graceful (the old key remains valid for some period)
3. If the chain is broken (say for a network outage), root resigning must occur

`opkl.json` after T1:

```json
{
  "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs": {
    "iss": "https://token.actions.githubusercontent.com",
    "nbf": 1698760418,
    "exp": null,
    "sts": "valid",
    "signatures" : [
      {
        "keyid": "1bf1c6e3cdd3d3a8420b19199e27511999850f4b376c4547b2f32fba7e80fca3",
        "thumprint": "OzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xt",
        "sig": "...opk..."
      }
    ],
    "jwk": {
           "n": "... <modulus> ...",
           "kty": "RSA",
           "kid": "1F2AB83404C08EC9EA0BB99DAED02186B091DBF4",
           "alg": "RS256",
           "e": "AQAB",
           "use": "sig",
           "x5c": ["... <x509 cert chain> ..."],
           "x5t": "Hyq4NATAjsnqC7mdrtAhhrCR2_Q"
         }
  },
  "OzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xt": {
      "iss": "https://token.actions.githubusercontent.com",
      "nbf": 1698760417,
      "exp": null,
      "sts": "valid",
      "jwk": {
            "n": "... <modulus> ...",
            "kty": "RSA",
            "kid": "2F2AB83404C08EC9EA0BB99DAED02186B091DBF5",
            "alg": "RS256",
            "e": "AQAB",
            "use": "sig",
            "x5c": ["... <x509 cert chain> ..."],
            "x5t": "Iyq4NATAjsnqC7mdrtAhhrCR2_L"
       }
   }
}
```

`opkl.json` after T2:

```json
{
  "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs": {
    "iss": "https://token.actions.githubusercontent.com",
    "nbf": 1698760418,
    "exp": null,
    "sts": "valid",
    "signatures" : [
      {
        "keyid": "1bf1c6e3cdd3d3a8420b19199e27511999850f4b376c4547b2f32fba7e80fca3",
        "thumprint": "OzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xt",
        "sig": "...opk..."
      }
    ],
    "jwk": {
           "n": "... <modulus> ...",
           "kty": "RSA",
           "kid": "1F2AB83404C08EC9EA0BB99DAED02186B091DBF4",
           "alg": "RS256",
           "e": "AQAB",
           "use": "sig",
           "x5c": ["... <x509 cert chain> ..."],
           "x5t": "Hyq4NATAjsnqC7mdrtAhhrCR2_Q"
         }
  },
  "OzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xt": {
      "iss": "https://token.actions.githubusercontent.com",
      "nbf": 1698760417,
      "exp": null,
      "sts": "valid",
      "jwk": {
            "n": "... <modulus> ...",
            "kty": "RSA",
            "kid": "2F2AB83404C08EC9EA0BB99DAED02186B091DBF5",
            "alg": "RS256",
            "e": "AQAB",
            "use": "sig",
            "x5c": ["... <x509 cert chain> ..."],
            "x5t": "Iyq4NATAjsnqC7mdrtAhhrCR2_L"
       }
   },
  "PzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xu": {
      "iss": "https://token.actions.githubusercontent.com",
      "nbf": 1698760416,
      "exp": null,
      "sts": "valid",
      "jwk": {
            "n": "... <modulus> ...",
            "kty": "RSA",
            "kid": "3F2AB83404C08EC9EA0BB99DAED02186B091DBF6",
            "alg": "RS256",
            "e": "AQAB",
            "use": "sig",
            "x5c": ["... <x509 cert chain> ..."],
            "x5t": "Jyq4NATAjsnqC7mdrtAhhrCR2_M"
       }
   }
}
```

TODO:

* How is the public key log used by other roles and and clients?
* Describe how to deal with online OpenPubkey role compromise
* Can we use GQ signatures safely for the public key log? I think so. If not, full OpenPubkey signing would change the flow slightly, but should be fixable by adding both OIDC public keys to the CIC

## Implementation options considered
1. Use a delegated target role to manage the OIDC public keys log
   * **Rejected**: using target files for TUF metadata signature verification breaks a core TUF constraint that signatures should be verified before taget files are retrieved and processed
2. Use offline keys to manage OIDC public keys, and use OpenPubkey just for target roles (similar to per TAP-18)
   * **Rejected**: this doesn't reduce the complexity of setting up and managing TUF sufficiently to make this TAP of sufficient value to pursue as is, but might make another good TAP?
3. Invent a new role that is triggered by OIDC public key rotation (presumably via polling) signed using OpenPubkey
   * **Evaluate**
   * Pros
      * Doesn't confuse the behavior of existing roles that are well defined and understood
   * Cons
      * Larger change, which might impact compatibility etc
      * Role doesn't seem generic enough to become part of core roles
4. Modify the Timestamp role to support adding additional metadata files containing the OIDC public keys.
   * **Selected**
   * Pros
     * Relatively natural fit becaues this runs regularly anyway
   * Cons
     * Potentially confuses a well understood role, and couples logging to timestamping

# Open Questions
* Do OIDC provider use any other mechanism to announcing key revocation other than by removing from the JWKS endpoint?
  * e.g. social media, blogs etc.

# Threat Analysis

# Backwards Compatibility

Clients that do not recognize OpenPubkey certs will not be able to validate signatures from them, but they will be able to parse the metadata as normal

# Augmented Reference Implementation

TBC

# Copyright
This document has been placed in the public domain.

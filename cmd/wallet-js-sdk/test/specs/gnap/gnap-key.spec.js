/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import { expect } from "chai";
import { v4 as uuidv4 } from "uuid";
import { loadFrameworks, testConfig } from "../common";
import { WalletUser } from "../../../src";

const JOHN_USER = "john-agent";

let john;

describe("GNAP key tests", async function () {
  it("Init agent with valid GNAP key", async function () {
    let keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign', 'verify']
    );

    let exportedJwk = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);

    john = await loadFrameworks({
      name: JOHN_USER,
      gnapKey: JSON.stringify(exportedJwk),
    }).catch(function (reason) {
      expect.fail(reason.toString())
    });

    john ? john.destroy() : "";
  });

  it("Fail to init with invalid GNAP key", async function () {
    let gnapKey = {
      "kty": "EC",
      "kid": "key1",
      "crv": "AAAAA",
      "alg": "AAAAA",
      "x": "44-NZpsA5VWHwaXc4ooMM6n6Sjvfs7KIbhyGUuGIHBE",
      "y": "ZRgTWih577UvUkorr0NjCNIGyk9Ps0uesXpTCp55FKc",
      "d": "o4ifzO3ya2gQsKFZ-CNbRFbG19AnkZ3NcN5X-VO3CLI"
    }

    john = await loadFrameworks({
      name: JOHN_USER,
      gnapKey: JSON.stringify(gnapKey),
    }).catch(function (reason) {
      expect(reason.toString()).to.contain("failed to unmarshal gnap JWK")
    });

    john ? john.destroy() : "";
  });

  it("has no gnap key", async function () {
    john = await loadFrameworks({
      name: JOHN_USER,
      // gnapKey: JSON.stringify(gnapKey),
    }).catch(function (reason) {
      expect(reason.toString()).to.contain("AAAAAAAA")
    });

    john ? john.destroy() : "";
  });
});

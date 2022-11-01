/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import chai, {expect} from 'chai';
import moxios from 'moxios';
import {authorize} from '@';

describe('OpenID4CI Tests', async function(){
  beforeEach(function () {
    moxios.install();
  });

  afterEach(function () {
    moxios.uninstall();
  });

  const defaultIssuerURI = 'issuer.example.com'
  const walletCallbackURI = 'wallet.example.com/cb'
  const userDID = 'did:example:foo'
  const clientID = '12345'

  it('authorization code flow success', async function(done) {
    moxios.stubRequest('GET', defaultIssuerURI + '/.well-known/openid-configuration', {
      issuer: defaultIssuerURI,
      authorization_endpoint: defaultIssuerURI + '/auth',
      token_endpoint: defaultIssuerURI + '/token',
      pushed_authorization_request_endpoint: defaultIssuerURI + '/par',
      require_pushed_authorization_requests: true,
      credential_endpoint: defaultIssuerURI + '/credentials',
    });

    moxios.stubRequest('POST', '/par', {request_uri: 'request-uri-value', expires_in: 60});

    const issuanceRequest = {
      issuer: defaultIssuerURI,
      credential_type: 'credential_type',
      user_pin_required: true,
      op_state: 'op_state_value',
    };

    const {redirect, client_state} = await authorize(issuanceRequest, '', {
      wallet_callback_uri: walletCallbackURI,
      user_did: userDID,
      client_id: clientID,
    });

    expect(redirect).to.not.undefined;

    done();
  });
});

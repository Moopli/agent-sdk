/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import axios from "axios";
import { encode, decode } from "js-base64";

/**
 * OpenID4CI module provides APIs for wallets to receive verifiable credentials through OIDC for Credential Issuance.
 *
 * @module OpenID4CI
 *
 */

/**
 * authorize is used by a wallet to authorize an issuer's OIDC verifiable-credential Issuance Request.
 *
 * @param{Object} req - the Issuance Request from an OIDC Issuer that the wallet intends to authorize.
 * @param{string} user_pin - Optional. A 2FA PIN provided by the Issuer to the wallet through a separate channel
 * from the request, for pre-authorized issuance flows.
 * @param{Object} client_config -
 * @param{string} client_config.wallet_callback_uri - wallet-hosted URI for callback redirect from issuer, after user authorizes issuer.
 * @param{string} client_config.user_did - the DID of the wallet user. The requested credential will be bound to this DID.
 * @param{string} client_config.client_id - the wallet app instance's OIDC client ID.
 * @param{function} jwt_signer
 *
 */
export async function authorize(
  req,
  user_pin = '',
  client_config,
  jwt_signer = async function(iss, aud, iat, c_nonce){return ''},
) {
  const {issuer, credential_type, user_pin_required, op_state} = req;
  const pre_auth_code = req['pre-authorized_code'];

  if (pre_auth_code !== '' && pre_auth_code !== undefined) {
    if (user_pin_required === true && user_pin === '') {
      throw new Error("Issuance Request indicates a user PIN is required, but no user PIN was provided.");
    }

    return await preauthorized(issuer, credential_type, pre_auth_code, user_pin, client_config, jwt_signer)
  }

  return await request_issuance(issuer, credential_type, op_state, client_config);
}

/**
 * request_issuance begins performs a pushed authorization request to the issuer, and returns a redirect URI and client state.
 *
 * @param {string} issuer_uri - uri of issuer server.
 * @param {string} credential_type - type of credential to request, as found in the Issuance Request.
 * @param {string} op_state - (optional) op_state parameter for issuer-initiated transactions.
 * @param {object} client_config - client configuration.
 * @param {string} client_config.wallet_callback_uri - wallet-hosted URI for callback redirect from issuer, after user authorizes issuer.
 // * @param {string} client_config.user_did - the DID of the wallet user. The requested credential will be bound to this DID.
 * @param {string} client_config.client_id - the wallet app instance's OIDC client ID.
 *
 *
 * @returns {Object} - If successful, returns the redirect URI for redirecting to the Issuer for user consent,
 * and a client state string to be saved and provided to the followup wallet callback.
 */
async function request_issuance(
  issuer_uri ,
  credential_type ,
  op_state = '',
  client_config ,
) {
  const issuer_metadata = await get_issuer_metadata(issuer_uri);

  const oauth_state = generate_nonce();

  const authRequest = new URLSearchParams();
  authRequest.append('response_type', 'code');
  authRequest.append('client_id', client_config.client_id);
  authRequest.append('redirect_uri', client_config.wallet_callback_uri);
  authRequest.append('state', oauth_state);
  authRequest.append('op_state', op_state);
  authRequest.append('authorization_details', JSON.stringify([
    {
      type: 'openid_credential',
      credential_type: credential_type,
    }
  ]));

  const {request_uri, expires_in} = await axios.post(
    issuer_metadata.pushed_authorization_request_endpoint,
    authRequest,
  ).then((resp) => resp.data);

  const redirect_to_issuer = new URL(issuer_metadata.authorization_endpoint);
  redirect_to_issuer.searchParams.append('request_uri', request_uri);
  redirect_to_issuer.searchParams.append('client_id', client_config.client_id);

  const transaction_data = {
    credential_type,
    client_id: client_config.client_id,
    issuer_metadata,
    oauth_state,
  };

  return {redirect: redirect_to_issuer.href, client_state: marshal_transaction(transaction_data)};
}

/**
 * callback is the OIDC issuance callback, used when the issuer has returned to the wallet, and the wallet user
 * has consented to have the credential created.
 *
 * @param {string} callback_uri
 * @param {string} client_state
 * @param {Object} client_config
 * @param {string} client_config.user_did - the DID of the wallet user to whom the credential is being issued.
 * @param {string} client_config.wallet_callback_uri - wallet-hosted URI for callback redirect from issuer, after user authorizes issuer.
 * @param {string} client_config.client_id - the wallet app instance's OIDC client ID. * @param {Object} client_state
 * @param {function} jwt_signer - a handler for signing a JWT for proving possession of user_did.
 *    When this creates a JWT, it should add kid, jwk, or x5c field corresponding to a key bound to user_did.
 */
export async function callback(
  callback_uri,
  client_state,
  client_config,
  jwt_signer = async function(iss, aud, iat, c_nonce){return ''},
) {
  const parsedURI = new URL(callback_uri);

  const authorization_code = parsedURI.searchParams.get('code');
  const oauth_state = parsedURI.searchParams.get('state');

  if (authorization_code === '') {
    throw new Error('Callback URI is missing authorization `code` as a query parameter.');
  }

  if (oauth_state === '') {
    throw new Error('Issuer did not include state parameter in callback URI when returning user to wallet.')
  }

  if (client_state === '') {
    throw new Error('Cannot complete authorization flow, `callback` must be provided with client_state string returned by ' +
      'previous `authorize` call.')
  }

  const transaction_data = parse_transaction(client_state);

  if (transaction_data.oauth_state !== oauth_state) {
    throw new Error('Issuer provided a state parameter that does not match the state parameter of the client-side transaction. ' +
      'This may be an error in the Issuer, or a mix-up of state data in a client performing multiple flows at the same time.')
  }

  const tokenRequest = new URLSearchParams();
  tokenRequest.append('grant_type', 'authorization_code');
  tokenRequest.append('code', authorization_code);
  tokenRequest.append('redirect_uri', client_config.wallet_callback_uri);
  tokenRequest.append('client_id', client_config.client_id);

  /*
  response format:
  {
    access_token: '',
    token_type: '',
    c_nonce: '',
  }
  */
  const token_response = await axios.post(
    transaction_data.issuer_metadata.token_endpoint,
    tokenRequest,
    ).then((resp) => resp.data).catch((e) => {
    throw new Error('Error authorizing wallet with Issuer: failed to exchange auth code for token:', e);
  });

  return await get_credential(token_response, transaction_data, client_config, jwt_signer);
}

async function preauthorized(
  issuer_uri,
  credential_type,
  pre_authorized_code,
  user_pin,
  client_config,
  jwt_signer = async function(iss, aud, iat, c_nonce){return ''},
) {
  // no op_state for pre-auth flow
  // no oauth state for pre-auth flow

  const issuer_metadata = await get_issuer_metadata(issuer_uri);
  let transaction_data = {
    issuer_metadata,
    credential_type,
    client_id: client_config.client_id,
  }

  const tokenRequest = new URLSearchParams();
  tokenRequest.append('grant_type', 'urn:ietf:params:oauth:grant-type:pre-authorized_code');
  tokenRequest.append('pre-authorized_code', pre_authorized_code);
  tokenRequest.append('user_pin', user_pin);

  /*
  * tokenResponse contents look like:
  * {
      access_token: 'foobar',
      token_type: 'bearer',
      c_nonce: 'sldkfyhsiudlfkgjh',
      authorization_pending: true,
      interval: 5,
    }
  * */
  // TODO: POST as application/x-www-form-urlencoded not json
  let token_response = await axios.post(
    transaction_data.issuer_metadata.token_endpoint,
    tokenRequest,
  ).then((resp)=> resp.data);
  // TODO: poll if response is deferred (if token_response.authorization_pending is true),
  //  waiting token_response.interval seconds before next request (or 5 seconds if interval missing or less than 5).

  return await get_credential(token_response, transaction_data, client_config, jwt_signer);
}

async function get_credential(
  token_response,
  transaction_data,
  client_config = {
    user_did: '',
  },
  jwt_signer = async function(iss, aud, iat, c_nonce){return ''},
) {
  const jwt = await jwt_signer(transaction_data.client_id, transaction_data.issuer_metadata.issuer, /*time now*/0, token_response.c_nonce)

  const credentialRequest = {
    type: transaction_data.credential_type,
    // format: '', // TODO should we specify format, or allow issuer to always decide by default?
    did: client_config.user_did,
    proof: {
      proof_type: 'jwt',
      jwt,
    },
  };

  /*
  Response format:
  {
    format: '',
    credential: {},
  }
  */
  const credentialResponse = await axios.post(transaction_data.issuer_metadata.credential_endpoint, credentialRequest, {
    headers: {
      Authorization: "Bearer " + token_response.access_token,
    },
  }).then((resp) => resp.data);
  // TODO deferred flow implementation deferred

  return {format: credentialResponse.format, credential: credentialResponse.credential};
}


/*
get_issuer_metadata returns issuer metadata from the .well-known/openid-configuration endpoint.
{
  issuer: uri,
  authorization_endpoint: uri + '/auth',
  token_endpoint: uri + '/token',
  pushed_authorization_request_endpoint: uri + '/par',
  require_pushed_authorization_requests: true,
  credential_endpoint: uri + '/credentials',
}
*/
async function get_issuer_metadata(issuer_uri) {
  return await axios.get(issuer_uri + '/.well-known/openid-configuration')
    .then((resp) => resp.data)
    .catch((e) => {
      throw new Error('Failed to fetch issuer server metadata:', e)
    });
}

function parse_transaction(txn) {
  return JSON.parse(decode(txn))
}

function marshal_transaction(txn) {
  return encode(JSON.stringify(txn), true)
}

function generate_nonce() {
  return crypto.randomUUID();
}
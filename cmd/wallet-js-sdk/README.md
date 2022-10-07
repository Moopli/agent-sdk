[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/edge-agent/main/LICENSE)

# Wallet SDK

Wallet JavaScript SDK for user agent wallet operations. 

# Documentation

Refer this [documentation](docs/wallet_sdk.md) to learn more about wallet SDK.

# Pre requisite

In order to successfully run tests in this wallet package, you must first build and install [agent-js-workder](../agent-js-worker/README.md).

# Build it

Run `npm install` in this directory. The output bundles will be placed in `dist/`.

# Test

Run `npm test` in this directory to run tests. 

# Dev

- Run `npm run dev` in this directory. The output dev mode bundles will be placed in `dist/`.

You can also run following command to test your changes.

- `npm run test:setup` to setup test assets and start containers.
- `npm run test:start` can be run multiple times.
- `npm run test:dev` to launch test with Chrome.
- `npm run test:teardown` to bring down containers and cleanup tests.

# Update API reference docs

Run `npm run docs` to update API reference docs.

## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.

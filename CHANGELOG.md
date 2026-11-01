# Changelog

## [0.2.4](https://github.com/goncaloneves/veil/compare/v0.2.3...v0.2.4) (2026-11-01)


### Bug Fixes

* the password rule skips code: a word-only identifier before , ) } ; or ] and a {…} template expression ([04811c1](https://github.com/goncaloneves/veil/commit/04811c1f7d5d26191a886a81639e5fd25e798361))
* the sql-password rule no longer reads a quoted password key, as in PHP arrays and CSS selectors, as a SQL password ([397c3cd](https://github.com/goncaloneves/veil/commit/397c3cd29dcf5e18fc3a216927884f0d7e4f3752))

## [0.2.3](https://github.com/goncaloneves/veil/compare/v0.2.2...v0.2.3) (2026-11-01)


### Bug Fixes

* stop masking project names, image tags and code that is not a secret ([b2a8530](https://github.com/goncaloneves/veil/commit/b2a85303928ca18df2291e5e17feb0e5d49b0c35))

## [0.2.2](https://github.com/goncaloneves/veil/compare/v0.2.1...v0.2.2) (2026-11-01)


### Bug Fixes

* mask known values in large base64 strings and refuse edits when a check fails ([7a21ef9](https://github.com/goncaloneves/veil/commit/7a21ef982a79c4b681f2c5cec5b48d9e2995c60e))


### Documentation

* every claim checked against the code, verified agent setups, and tests that tie the docs to the code ([ca9a9c5](https://github.com/goncaloneves/veil/commit/ca9a9c5a7bcec27c7b4c3dadc8dddff5d8e74d72))
* the architecture diagram shows every agent, secret files kept current and the full restore rule ([ef87b56](https://github.com/goncaloneves/veil/commit/ef87b56876598b730c1b01836d762dcdfb827221))

## [0.2.1](https://github.com/goncaloneves/veil/compare/v0.2.0...v0.2.1) (2026-10-31)


### Bug Fixes

* **cli:** `--help` after any command, proxy paths read from the folder it starts in, and accurate help and starter config text ([619290c](https://github.com/goncaloneves/veil/commit/619290ca7bc0f08571377b185d6a10a616dbe111))


### Documentation

* install, update and check veil for every agent, and correct claims that did not match the code ([69063ab](https://github.com/goncaloneves/veil/commit/69063ab2f32643d88ac5ed9f186a567ffe3eb591))

## [0.2.0](https://github.com/goncaloneves/veil/compare/v0.1.0...v0.2.0) (2026-10-31)


### Features

* **core:** mask known values in every listed encoding and catch more secret formats ([bf40ce6](https://github.com/goncaloneves/veil/commit/bf40ce66a9e3d1835a4c3ab58d7360df10c65d00))
* **sources:** load secrets from their usual places on macOS, Linux, servers and Windows ([2e18f5d](https://github.com/goncaloneves/veil/commit/2e18f5dbc46352324292640e74f2c93450e024ea))
* veil works with any agent through native plugins for Pi and opencode and a local proxy ([e122b14](https://github.com/goncaloneves/veil/commit/e122b1457c7b5b5c876dfb166e18362995dad7a0))
* **build:** Windows and baseline x64 binaries, adapter bundles in each release, and safer installers ([4c45348](https://github.com/goncaloneves/veil/commit/4c453484895e45ff5ad9cd8f67c97ebd25715bf2))


### Documentation

* a logo, an architecture diagram and a clearer README ([614bdcb](https://github.com/goncaloneves/veil/commit/614bdcb347340ad25c2ab161dddf2b1e3c53aca6))
* list zero runtime dependencies among veil's benefits ([b3d09af](https://github.com/goncaloneves/veil/commit/b3d09af4d62da43e78323e3762958e9f89350b0c))
* what veil masks, how to set it up for each agent, and its limits ([ad3a3fa](https://github.com/goncaloneves/veil/commit/ad3a3fae6b72f9e90e71b00db64ba2a14ffcf48a))

## 0.1.0 (2026-10-31)


### Features

* veil, masks your secrets before your coding agent's model sees them ([ff5674e](https://github.com/goncaloneves/veil/commit/ff5674eb754db71aa087e605623e15e6c4c5ef69))

<h1 align="center">nessus.js by <a href="https://turingsecure.com" target="_blank">turingsecure.</a></h1>
<p>
  <img alt="Version" src="https://img.shields.io/badge/version-0.0.1-blue.svg?cacheSeconds=2592000" />
  <a href="#" target="_blank">
    <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg" />
  </a>
</p>

> nessus.js is library to parse nessus output files into javascript.

## Installation

Install the `@turingsecure/nessus.js` package:

```sh
# use yarn or npm
yarn add @turingsecure/nessus.js
```

Import the library to use it in your code:

```js
import { NessusParser } from '@turingsecure/nessus.js'
```

## Usage

To parse an XML file, you just have to execute the imported function.

```js
const xml = 'nessus scan'
const parsed = NessusParser(xml)
```

## Contributing

Contributions, issues and feature requests are welcome.
Feel free to check out the [issues page](https://github.com/turingsecure/nessus.js/issues) if you want to contribute.

## License

Copyright © 2021 [turingsecure](https://turingsecure.com).
This project is [MIT](LICENSE) licensed.

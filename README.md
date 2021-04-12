# ldap-simple-tool

## What is it

This is a simple ldap tool inspired by https://github.com/shanghai-edu/ldap-test-tool.

## How to use it

### cli usage

1. Installation

   - If you have node installed, simple execute `npm i -g ldap-simple-tool` or `yarn global add ldap-simple-tool` or download `ldap-simple-tool`.

   - If you do not have node, download the latest binary according to your OS platform in [release](https://github.com/liudonghua123/ldap-simple-tool/releases) page.

2. Download the template config file via https://raw.githubusercontent.com/liudonghua123/ldap-simple-tool/master/cfg.conf.example, modify according to your actual environment. Place it in the cwd, the location of the script or the homedir, the priority of config location is cwd > script > homedir.

3. Run `ldap-simple-tool` in a terminal.

### lib usage

1. `npm i ldap-simple-tool` or `yarn add ldap-simple-tool`
2. import and use it

   ```js
   const { check, auth, search, filter } = require('ldap-simple-tool');
   // ...
   let authenticated = await check({ addr, bindDn, bindPass, tls, startTLS });
   let authResults = await auth({ addr, baseDn, bindDn, bindPass, authFilter, tls, startTLS }, [
     _,
     usernameOrFilePath,
     userPasswordOptional,
   ]);
   let searchResults = await search({ addr, baseDn, bindDn, bindPass, authFilter, tls, startTLS }, [
     _,
     usernameOrFilePath,
   ]);
   let filterResults = await filter({ addr, baseDn, bindDn, bindPass, authFilter, tls, startTLS }, [_, expression]);
   ```

## Todos

- [ ] add travis ci support.
- [ ] shrink the binary size.
- [ ] add more useful features.

## Snapshots

[![asciicast](https://asciinema.org/a/303916.svg)](https://asciinema.org/a/303916)

## LICENSE

MIT License

Copyright (c) 2020 liudonghua

#!/usr/bin/env node

const { showHelp } = require('yargs');
const chalk = require('chalk');
const { check, auth, search, filter } = require('../lib/index');
const { existsSync } = require('fs');
const { resolve } = require('path');

// https://github.com/yargs/yargs
const argv = require('yargs')
  .usage('Usage: $0 <command> [options]')
  .command('check', 'Performs a admin user bind operation against the LDAP server')
  .example('$0 check', 'Test admin user login')
  .command('auth', 'Performs a normal user bind operation against the LDAP server')
  .example('$0 auth username password', 'Auth a single normal user')
  .example('$0 auth filePath', 'Auth multi user from a file')
  .command('search', 'Performs a normal user search operation against the LDAP server')
  .example('$0 search username', 'search a single normal user')
  .example('$0 search filePath', 'search multi user from a file')
  .command('filter', 'Performs advanced filter operation against the LDAP server')
  .example('$0 filter expression', 'filter users')
  .alias('f', 'file')
  .describe('f', 'the configuration file')
  .default('f', './cfg.json')
  .help('h')
  .version('v')
  .alias('h', 'help')
  .alias('v', 'version')
  .epilog('Copyright (c) 2020 liudonghua').argv;

// read the basic configuration
let configFilePath = argv.file;
if (existsSync(resolve(argv.file))) {
  configFilePath = resolve(argv.file);
} else if (existsSync(resolve(process.cwd(), argv.file))) {
  configFilePath = resolve(process.cwd(), argv.file);
} else {
  console.info(chalk.yellow.italic(`configFilePath: ${argv.file} not exists`));
  process.exit(1);
}
// console.info(`process.cwd(): ${process.cwd()}, configFilePath: ${configFilePath}`);

const {
  ldap: { addr, baseDn, bindDn, bindPass, authFilter, attributes, tls, startTLS },
} = require(`${configFilePath}`);

const filterAttributeEntries = (entries, attributes) => {
  const result = {};
  entries.forEach(entry => attributes.forEach(attribute => (result[attribute] = entry[attribute])));
  return result;
};

(async () => {
  const [command] = argv._;
  switch (command) {
    case 'check':
      let authenticated = await check({ addr, bindDn, bindPass, tls, startTLS });
      if (authenticated) {
        console.info(chalk.blue.bold('check ok'));
      } else {
        console.info(chalk.yellow.italic('check fail'));
      }
      break;
    case 'auth':
      let authResults = await auth({ addr, baseDn, bindDn, bindPass, authFilter, tls, startTLS }, argv._);
      if (authResults && authResults.length > 0) {
        authResults = filterAttributeEntries(authResults, attributes);
        console.info(
          chalk.blue.bold(`auth ok, the user info is \n${chalk.magenta(JSON.stringify(authResults, null, 2))}`)
        );
      } else {
        console.info(chalk.yellow.italic('auth failed, please check the username or password'));
      }
      break;
    case 'search':
      let searchResults = await search({ addr, baseDn, bindDn, bindPass, authFilter, tls, startTLS }, argv._);
      if (searchResults && searchResults.length > 0) {
        searchResults = filterAttributeEntries(searchResults, attributes);
        console.info(
          chalk.blue.bold(`search ok, the user info is \n${chalk.magenta(JSON.stringify(searchResults, null, 2))}`)
        );
      } else {
        console.info(chalk.yellow.italic('search failed, please check the username'));
      }
      break;
    case 'filter':
      let filterResults = await filter({ addr, baseDn, bindDn, bindPass, authFilter, tls, startTLS }, argv._);
      if (filterResults && filterResults.length > 0) {
        filterResults = filterAttributeEntries(filterResults, attributes);
        console.info(
          chalk.blue.bold(`filter ok, the user info is \n${chalk.magenta(JSON.stringify(filterResults, null, 2))}`)
        );
      } else {
        console.info(chalk.yellow.italic('filter failed, please check the filter expression'));
      }
      break;
    case undefined:
      console.info(chalk.yellow.italic(`command is not specified, see help with -h.`));
      break;
    default:
      console.info(chalk.yellow.italic(`${command} is not support now! Please contact liudonghua@ynu.edu.cn.`));
      showHelp();
      break;
  }
})();

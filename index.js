#!/usr/bin/env node

// https://github.com/ldapts/ldapts
const { Client } = require('ldapts');
// https://github.com/liudonghua123/ldap-passwd
const { checkPassword, hashPassword } = require('ldap-passwd');

// https://github.com/shaozi/ldap-authentication
// https://github.com/chalk/chalk
// const { authenticate, LdapAuthenticationError } = require('ldap-authentication');

// https://alligator.io/nodejs/styling-output-command-line-node-scripts-chalk/
const chalk = require('chalk');

const { existsSync, readFileSync, createReadStream } = require('fs');
const readline = require('readline');

const { showHelp } = require('yargs');

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
  .default('f', 'cfg.json')
  .help('h')
  .version('v')
  .alias('h', 'help')
  .alias('v', 'version')
  .epilog('Copyright (c) 2020 liudonghua').argv;

// read the basic configuration
const {
  ldap: { addr, baseDn, bindDn, bindPass, authFilter, attributes, tls, startTLS },
} = require(`./${argv.file}`);

const _parseUsernamePasswordFile = filePath => {
  if (!existsSync(filePath)) {
    console.info(chalk.bgRed.yellow.italic(`you provided filePath ${filePath} not exists!`));
    return [];
  }
  return new Promise((resolve, reject) => {
    const usernamePasswords = [];
    let rl = readline.createInterface({
      input: createReadStream(filePath),
    });
    rl.on('line', line => {
      const splits = line.split(',');
      usernamePasswords.push({
        username: splits[0].trim(),
        userPassword: splits[1].trim(),
      });
    });
    rl.on('close', line => {
      resolve(usernamePasswords);
    });
    rl.on('error', error => {
      reject(error);
    });
  });
};

const _parseUsernameFile = filePath => {
  if (!existsSync(filePath)) {
    console.info(chalk.bgRed.yellow.italic(`you provided filePath ${filePath} not exists!`));
    return [];
  }
  return new Promise((resolve, reject) => {
    const usernames = [];
    let rl = readline.createInterface({
      input: createReadStream(filePath),
    });
    rl.on('line', line => {
      usernames.push({
        username: line.trim(),
      });
    });
    rl.on('close', line => {
      resolve(usernames);
    });
    rl.on('error', error => {
      reject(error);
    });
  });
};

const _authSingle = async (client, username, userPassword) => {
  console.info(chalk.bgGreen.blue.bold(`try to auth ${JSON.stringify({ username, userPassword })}!`));
  const { searchEntries, searchReferences } = await client.search(baseDn, {
    scope: 'sub',
    filter: authFilter.replace('%s', username),
  });
  const searchEntry = searchEntries[0];
  if (!searchEntry) {
    console.info(chalk.bgRed.yellow.italic(`user: ${username} not found!`));
    return null;
  }
  if (searchEntries.length > 1) {
    console.info(chalk.bgRed.yellow.italic(`multi user found, Use the first one!`));
  }
  const isPasswordMatch = checkPassword(userPassword, searchEntry.userPassword);
  if (!isPasswordMatch) {
    console.info(chalk.bgRed.yellow.italic(`user: ${username} password: ${userPassword} do not match`));
    return null;
  }
  return searchEntry;
};

const _searchSingle = async (client, username) => {
  console.info(chalk.bgGreen.blue.bold(`try to search ${JSON.stringify({ username })}!`));
  const { searchEntries, searchReferences } = await client.search(baseDn, {
    scope: 'sub',
    filter: authFilter.replace('%s', username),
  });
  const searchEntry = searchEntries[0];
  if (!searchEntry) {
    console.info(chalk.bgRed.yellow.italic(`user: ${username} not found!`));
    return null;
  }
  if (searchEntries.length > 1) {
    console.info(chalk.bgRed.yellow.italic(`multi user found, Use the first one!`));
  }
  return searchEntry;
};

const _filter = async (client, expression) => {
  console.info(chalk.bgGreen.blue.bold(`try to filter ${JSON.stringify({ expression })}!`));
  const { searchEntries, searchReferences } = await client.search(baseDn, {
    scope: 'sub',
    filter: expression,
  });
  return searchEntries;
};

const check = async () => {
  const client = new Client({
    url: `${tls ? 'ldaps' : 'ldap'}://${addr}`,
  });
  try {
    startTLS && client.startTLS();
    await client.bind(bindDn, bindPass);
    return true;
  } catch (error) {
    console.error(chalk.bgRed.yellow.italic(error));
    console.info(chalk.bgRed.yellow.italic('username and password do not match!'));
  } finally {
    await client.unbind();
  }
  return false;
};

const auth = async () => {
  const [_, username, userPassword] = argv._;
  const client = new Client({
    url: `${tls ? 'ldaps' : 'ldap'}://${addr}`,
  });
  try {
    startTLS && client.startTLS();
    await client.bind(bindDn, bindPass);
    // single search
    if (userPassword) {
      const searchEntry = await _authSingle(client, username, userPassword);
      return searchEntry ? [searchEntry] : [];
    }
    // multi search
    else {
      const filePath = username;
      const usernamePasswords = await _parseUsernamePasswordFile(filePath);
      return await Promise.all(
        usernamePasswords.map(({ username, userPassword }) => _authSingle(client, username, userPassword))
      );
    }
  } catch (error) {
    console.error(chalk.bgRed.yellow.italic(`auth operation error!\n${error}`));
  } finally {
    await client.unbind();
  }
  return null;
};

const search = async () => {
  const [_, username] = argv._;
  const client = new Client({
    url: `${tls ? 'ldaps' : 'ldap'}://${addr}`,
  });
  try {
    startTLS && client.startTLS();
    await client.bind(bindDn, bindPass);
    // multi search
    if (existsSync(username)) {
      const filePath = username;
      const usernames = await _parseUsernameFile(filePath);
      return await Promise.all(usernames.map(({ username }) => _searchSingle(client, username)));
    }
    // single search
    else {
      const searchEntry = await _searchSingle(client, username);
      return searchEntry ? [searchEntry] : [];
    }
  } catch (error) {
    console.error(chalk.bgRed.yellow.italic(`search operation error!\n${error}`));
  } finally {
    await client.unbind();
  }
  return null;
};

const filter = async () => {
  const [_, expression] = argv._;
  const client = new Client({
    url: `${tls ? 'ldaps' : 'ldap'}://${addr}`,
  });
  try {
    startTLS && client.startTLS();
    await client.bind(bindDn, bindPass);
    const filterResults = await _filter(client, expression);
    return filterResults;
  } catch (error) {
    console.error(chalk.bgRed.yellow.italic(`filter operation error!\n${error}`));
  } finally {
    await client.unbind();
  }
  return null;
};

(async () => {
  const [command] = argv._;
  switch (command) {
    case 'check':
      let authenticated = await check();
      if (authenticated) {
        console.info(chalk.bgGreen.blue.bold('check ok'));
      } else {
        console.info(chalk.bgRed.yellow.italic('check fail'));
      }
      break;
    case 'auth':
      let authResults = await auth();
      if (authResults) {
        console.info(
          chalk.bgGreen.blue.bold(
            `auth ok, the user info is \n${chalk.bgBlue.magenta(JSON.stringify(authResults, null, 2))}`
          )
        );
      } else {
        console.info(chalk.bgRed.yellow.italic('auth failed, please check the username or password'));
      }
      break;
    case 'search':
      let searchResults = await search();
      if (searchResults) {
        console.info(
          chalk.bgGreen.blue.bold(
            `search ok, the user info is \n${chalk.bgBlue.magenta(JSON.stringify(searchResults, null, 2))}`
          )
        );
      } else {
        console.info(chalk.bgRed.yellow.italic('search failed, please check the username'));
      }
      break;
    case 'filter':
      let filterResults = await filter();
      if (filterResults) {
        console.info(
          chalk.bgGreen.blue.bold(
            `filter ok, the user info is \n${chalk.bgBlue.magenta(JSON.stringify(filterResults, null, 2))}`
          )
        );
      } else {
        console.info(chalk.bgRed.yellow.italic('filter failed, please check the filter expression'));
      }
      break;
    case undefined:
      console.info(chalk.bgRed.yellow.italic(`command is not specified, see help with -h.`));
      break;
    default:
      console.info(chalk.bgRed.yellow.italic(`${command} is not support now! Please contact liudonghua@ynu.edu.cn.`));
      showHelp();
      break;
  }
})();

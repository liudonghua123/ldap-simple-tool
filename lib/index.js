// https://github.com/ldapts/ldapts
const { Client } = require('ldapts');
// https://github.com/liudonghua123/ldap-passwd
const { checkPassword, hashPassword } = require('ldap-passwd');

// https://github.com/shaozi/ldap-authentication
// https://github.com/chalk/chalk
// https://alligator.io/nodejs/styling-output-command-line-node-scripts-chalk/
const chalk = require('chalk');

const { existsSync, readFileSync, createReadStream } = require('fs');
const readline = require('readline');

const _parseUsernamePasswordFile = filePath => {
  if (!existsSync(filePath)) {
    console.info(chalk.yellow.italic(`you provided filePath ${filePath} not exists!`));
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
    console.info(chalk.yellow.italic(`you provided filePath ${filePath} not exists!`));
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

const _authSingle = async ({ baseDn, authFilter }, client, username, userPassword) => {
  console.info(chalk.blue.bold(`try to auth ${JSON.stringify({ username, userPassword })}!`));
  const { searchEntries, searchReferences } = await client.search(baseDn, {
    scope: 'sub',
    filter: authFilter.replace('%s', username),
    timeLimit: 0,
  });
  const searchEntry = searchEntries[0];
  if (!searchEntry) {
    console.info(chalk.yellow.italic(`user: ${username} not found!`));
    return null;
  }
  if (searchEntries.length > 1) {
    console.info(chalk.yellow.italic(`multi user found, Use the first one!`));
  }
  const isPasswordMatch = checkPassword(userPassword, searchEntry.userPassword);
  if (!isPasswordMatch) {
    console.info(chalk.yellow.italic(`user: ${username} password: ${userPassword} do not match`));
    return null;
  }
  return searchEntry;
};

const _searchSingle = async ({ baseDn, authFilter }, client, username) => {
  console.info(chalk.blue.bold(`try to search ${JSON.stringify({ username })}!`));
  const { searchEntries, searchReferences } = await client.search(baseDn, {
    scope: 'sub',
    filter: authFilter.replace('%s', username),
    timeLimit: 0,
  });
  const searchEntry = searchEntries[0];
  if (!searchEntry) {
    console.info(chalk.yellow.italic(`user: ${username} not found!`));
    return null;
  }
  if (searchEntries.length > 1) {
    console.info(chalk.yellow.italic(`multi user found, Use the first one!`));
  }
  return searchEntry;
};

const _filter = async ({ baseDn }, client, expression) => {
  console.info(chalk.blue.bold(`try to filter ${JSON.stringify({ expression })}!`));
  const { searchEntries, searchReferences } = await client.search(baseDn, {
    scope: 'sub',
    filter: expression,
    timeLimit: 0,
  });
  return searchEntries;
};

const check = async ({ addr, bindDn, bindPass, tls, startTLS }) => {
  const client = new Client({
    url: `${tls ? 'ldaps' : 'ldap'}://${addr}`,
  });
  try {
    startTLS && client.startTLS();
    await client.bind(bindDn, bindPass);
    return true;
  } catch (error) {
    console.error(chalk.yellow.italic(error));
    console.info(chalk.yellow.italic('username and password do not match!'));
  } finally {
    await client.unbind();
  }
  return false;
};

const auth = async ({ addr, baseDn, bindDn, bindPass, authFilter, tls, startTLS }, [_, username, userPassword]) => {
  const client = new Client({
    url: `${tls ? 'ldaps' : 'ldap'}://${addr}`,
  });
  try {
    startTLS && client.startTLS();
    await client.bind(bindDn, bindPass);
    // single search
    if (userPassword) {
      const searchEntry = await _authSingle({ baseDn, authFilter }, client, username, userPassword);
      return searchEntry ? [searchEntry] : [];
    }
    // multi search
    else {
      const filePath = username;
      const usernamePasswords = await _parseUsernamePasswordFile(filePath);
      return await Promise.all(
        usernamePasswords.map(({ username, userPassword }) =>
          _authSingle({ baseDn, authFilter }, client, username, userPassword)
        )
      );
    }
  } catch (error) {
    console.error(chalk.yellow.italic(`auth operation error!\n${error}`));
  } finally {
    await client.unbind();
  }
  return null;
};

const search = async ({ addr, baseDn, bindDn, bindPass, authFilter, tls, startTLS }, [_, username]) => {
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
      return await Promise.all(
        usernames.map(({ username }) => _searchSingle({ baseDn, authFilter }, client, username))
      );
    }
    // single search
    else {
      const searchEntry = await _searchSingle({ baseDn, authFilter }, client, username);
      return searchEntry ? [searchEntry] : [];
    }
  } catch (error) {
    console.error(chalk.yellow.italic(`search operation error!\n${error}`));
  } finally {
    await client.unbind();
  }
  return null;
};

const filter = async ({ addr, baseDn, bindDn, bindPass, authFilter, tls, startTLS }, [_, expression]) => {
  const client = new Client({
    url: `${tls ? 'ldaps' : 'ldap'}://${addr}`,
  });
  try {
    startTLS && client.startTLS();
    await client.bind(bindDn, bindPass);
    const filterResults = await _filter({ baseDn }, client, expression);
    return filterResults;
  } catch (error) {
    console.error(chalk.yellow.italic(`filter operation error!\n${error}`));
  } finally {
    await client.unbind();
  }
  return null;
};

module.exports = { check, auth, search, filter };

// https://github.com/ldapts/ldapts
const { Client } = require('ldapts');
// https://github.com/liudonghua123/ldap-passwd
const { checkPassword, hashPassword } = require('ldap-passwd');

// https://github.com/shaozi/ldap-authentication
// https://github.com/chalk/chalk
// const { authenticate, LdapAuthenticationError } = require('ldap-authentication');

// https://alligator.io/nodejs/styling-output-command-line-node-scripts-chalk/
const chalk = require('chalk');

const { showHelp } = require('yargs');

// https://github.com/yargs/yargs
const argv = require('yargs')
  .usage('Usage: $0 <command> [options]')
  .command('auth', 'Performs a admin user bind operation against the LDAP server')
  .example('$0 auth', 'Test admin user login')
  .command('login', 'Performs a normal user bind operation against the LDAP server')
  .example('$0 login username password', 'Test normal user login')
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

const auth = async () => {
  const client = new Client({
    url: `ldap${tls ? 's' : ''}://${addr}`,
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

const login = async () => {
  const [_, username, userPassword, usernameAttribute = 'uid'] = argv._;
  const client = new Client({
    url: `ldap${tls ? 's' : ''}://${addr}`,
  });
  try {
    startTLS && client.startTLS();
    await client.bind(bindDn, bindPass);
    const { searchEntries, searchReferences } = await client.search(baseDn, {
      scope: 'sub',
      filter: authFilter.replace('%s', username),
    });
    const searchEntry = searchEntries[0];
    if (!searchEntry) {
      console.info(chalk.bgRed.yellow.italic(`no user found!`));
      return null;
    }
    if (searchEntries.length > 1) {
      console.info(chalk.bgRed.yellow.italic(`multi user found, Use the first one!`));
    }
    const isPasswordMatch = checkPassword(userPassword, searchEntry.userPassword);
    if (!isPasswordMatch) {
      console.info(chalk.bgRed.yellow.italic(`user password do not match`));
      return null;
    }
    return searchEntry;
  } catch (error) {
    console.error(chalk.bgRed.yellow.italic(error));
    console.info(chalk.bgRed.yellow.italic('username and password do not match!'));
  } finally {
    await client.unbind();
  }
  return null;
};

(async () => {
  const [command] = argv._;
  switch (command) {
    case 'auth':
      let authenticated = await auth();
      if (authenticated) {
        console.info(chalk.bgGreen.blue.bold('auth ok'));
      } else {
        console.info(chalk.bgRed.yellow.italic('auth fail'));
      }
      break;
    case 'login':
      let authenticateInfo = await login();
      if (authenticateInfo) {
        console.info(
          chalk.bgGreen.blue.bold(
            `login ok, the user info is \n${chalk.bgBlue.magenta(JSON.stringify(authenticateInfo, null, 2))}`
          )
        );
      } else {
        console.info(chalk.bgRed.yellow.italic('login failed, please check the username or password'));
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

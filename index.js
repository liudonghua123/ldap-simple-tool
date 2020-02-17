// https://github.com/ldapts/ldapts
// const { Client } = require('ldapts');

// https://github.com/shaozi/ldap-authentication
// https://github.com/chalk/chalk
const { authenticate, LdapAuthenticationError } = require('ldap-authentication');

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
const { ldap } = require(`./${argv.file}`);

const auth = async () => {
  let authenticated = false;
  try {
    authenticated = await authenticate({
      ldapOpts: { url: `ldap://${ldap.addr}` },
      userDn: ldap.bindDn,
      userPassword: ldap.bindPass,
    });
    return authenticated;
  } catch (error) {
    if (error.name === 'InvalidCredentialsError') {
      console.info(chalk.bgRed.yellow.italic('username and password do not match!'));
    }
  }
  return authenticated;
};

const login = async () => {
  let authenticateInfo = null;
  const [_, username, userPassword, usernameAttribute = 'uid'] = argv._;
  try {
    authenticateInfo = await authenticate({
      ldapOpts: { url: `ldap://${ldap.addr}` },
      adminDn: ldap.bindDn,
      adminPassword: ldap.bindPass,
      userSearchBase: ldap.baseDn,
      username: username.toString(),
      userPassword: userPassword.toString(),
      usernameAttribute,
    });
    return authenticateInfo;
  } catch (error) {
    if (error.name === 'InvalidCredentialsError') {
      console.info(chalk.bgRed.yellow.italic('username and password do not match!'));
    }
  }
  return authenticateInfo;
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

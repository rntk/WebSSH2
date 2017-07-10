// util/index.js

// private
require('colors') // allow for color property extensions in log messages
var debug = require('debug')('WebSSH2')
var Auth = require('basic-auth')
var executor = require('child_process').exec

exports.basicAuth = function basicAuth (req, res, next) {
  var myAuth = Auth(req)
  if (myAuth && (myAuth.name === req.app.locals.auth.user) && (myAuth.pass === req.app.locals.auth.password)) {
    res.locals.authorized = true
    next()
  } else {
    res.statusCode = 401
    debug('basicAuth credential request (401)')
    res.setHeader('WWW-Authenticate', 'Basic realm="WebSSH"')
    res.end('Username and password required for web SSH service.')
  }
}

exports.sshAuth = function sshAuth (req, res, next) {
  if (res.locals.authorized) {
    if (req.app.locals.auth.credentials) {
      executor(req.app.locals.auth.credentials + ' ' + req.params.host, function (error, stdout, stderr) {
        if (error) {
          debug('Can`t get ssh auth configuration')
          res.end('Can`t get ssh auth configuration')
        } else {
          try {
            var auth = JSON.parse(stdout)
            if (!req.session.ssh) {
              req.session.ssh = {}
            }
            req.session.ssh.user = auth.login
            req.session.ssh.password = auth.password
            next()
          } catch (e) {
            debug('Can`t parse ssh auth configuration. Info: ' + e.message)
            res.end('Can`t get ssh auth configuration')
          }
        }
      })
    } else {
      debug('Wrong ssh auth configuration')
      res.end('Wrong ssh auth configuration')
    }
  } else {
    res.statusCode = 401
    debug('basicAuth credential request (401)')
    res.setHeader('WWW-Authenticate', 'Basic realm="WebSSH"')
    res.end('Username and password required for web SSH service.')
  }
}

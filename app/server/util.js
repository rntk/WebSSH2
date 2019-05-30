'use strict'
/* jshint esversion: 6, asi: true, node: true */
// util.js

// private
require('colors') // allow for color property extensions in log messages
var debug = require('debug')('WebSSH2')
var Auth = require('basic-auth')
var executor = require('child_process').exec

exports.basicAuth = function basicAuth (req, res, next) {
  var myAuth = Auth(req)
  if (myAuth && myAuth.pass !== '') {
    req.session.username = myAuth.name
    req.session.userpassword = myAuth.pass
    debug('myAuth.name: ' + myAuth.name.yellow.bold.underline +
      ' and password ' + ((myAuth.pass) ? 'exists'.yellow.bold.underline
      : 'is blank'.underline.red.bold))
    next()
  } else {
    res.statusCode = 401
    debug('basicAuth credential request (401)')
    res.setHeader('WWW-Authenticate', 'Basic realm="WebSSH"')
    res.end('Username and password required for web SSH service.')
  }
}

// takes a string, makes it boolean (true if the string is true, false otherwise)
exports.parseBool = function parseBool (str) {
  return (str.toLowerCase() === 'true')
}

exports.sshAuth = function sshAuth (req, res, next) {
  if (req.app.locals.auth.credentials) {
    executor(req.app.locals.auth.credentials + ' ' + req.params.host, function (error, stdout, stderr) {
      if (error) {
        debug('Can`t get ssh auth configuration')
        res.end('Can`t get ssh auth configuration')
      } else {
        try {
          var auth = JSON.parse(stdout)
          if (!req.session) {
            req.session = {}
          }
          req.session.username = auth.login
          req.session.userpassword = auth.password
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
}
 * Copyright (c) 2014-2022 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
document.write(window.location.search);
/*
 * Copyright (c) 2014-2022 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

console.log("Hello world")

document.write("Hello world");

function endsWith(x, y) {
  return x.lastIndexOf(y) === x.length - y.length;
}


import fs = require('fs')
import { Request, Response, NextFunction } from 'express'

const utils = require('../lib/utils')
const challenges = require('../data/datacache').challenges
const libxml = require('libxmljs2')
const os = require('os')
const vm = require('vm')
const unzipper = require('unzipper')
const path = require('path')

function matchesSystemIniFile (text) {
  const match = text.match(/(; for 16-bit app support|drivers|mci|driver32|386enh|keyboard|boot|display)/gi)
  return match && match.length >= 2
}

function matchesEtcPasswdFile (text) {
  const match = text.match(/\w*:\w*:\d*:\d*:\w*:.*/gi)
  return match && match.length >= 2
}

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file) {
    next()
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (file?.buffer && !utils.disableOnContainerEnv()) {
      const buffer = file.buffer
      const filename = file.originalname.toLowerCase()
      const tempFile = path.join(os.tmpdir(), filename)
      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { next(err) }
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { next(err) }
          fs.close(fd, function () {
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const fileName = entry.path
                const absolutePath = path.resolve('uploads/complaints/' + fileName)
                utils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
                if (absolutePath.includes(path.resolve('.'))) {
                  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err) }))
                } else {
                  entry.autodrain()
                }
              }).on('error', function (err) { next(err) })
          })
        })
      })
    }
    res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  utils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  utils.solveIf(challenges.uploadTypeChallenge, () => {
    return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip')
  })
  next()
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    utils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (file?.buffer && !utils.disableOnContainerEnv()) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
      const data = file.buffer.toString()
      try {
        const sandbox = { libxml, data }
        vm.createContext(sandbox)
        const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })
        const xmlString = xmlDoc.toString(false)
        utils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return (matchesSystemIniFile(xmlString) || matchesEtcPasswdFile(xmlString)) })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'))
      } catch (err) {
        if (utils.contains(err.message, 'Script execution timed out')) {
          if (utils.notSolved(challenges.xxeDosChallenge)) {
            utils.solve(challenges.xxeDosChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  res.status(204).end()
}

module.exports = {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload
}
document.write(window.location.search);


document.write(window.location.search);
/*
This ^^ causes an alert that won't be reported in the PR because
it was already in the code.
*/

// 2
require('crypto').createCipheriv('aes-256-cfb', '0123456789bbbbbb0123456789bbbbbb', '0123456789bbbbbb');


// 3
require('crypto').createCipheriv('aes-256-cfb', '0123456789cccccc0123456789cccccc', '0123456789cccccc');


// 4
require('crypto').createCipheriv('aes-256-cfb', '0123456789dddddd0123456789dddddd', '0123456789dddddd');


// 5
require('crypto').createCipheriv('aes-256-cfb', '0123456789eeeeee0123456789eeeeee', '0123456789eeeeee');


// 6
require('crypto').createCipheriv('aes-256-cfb', '0123456789ffffff0123456789ffffff', '0123456789ffffff');


// 7
require('crypto').createCipheriv('aes-256-cfb', '0123456789gggggg0123456789gggggg', '0123456789gggggg');


// 8
require('crypto').createCipheriv('aes-256-cfb', '0123456789hhhhhh0123456789hhhhhh', '0123456789hhhhhh');


// 9
require('crypto').createCipheriv('aes-256-cfb', '0123456789iiiiii0123456789iiiiii', '0123456789iiiiii');


// 10
require('crypto').createCipheriv('aes-256-cfb', '0123456789jjjjjj0123456789jjjjjj', '0123456789jjjjjj');

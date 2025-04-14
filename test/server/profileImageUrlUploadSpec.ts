/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon = require('sinon')
import chai = require('chai')
import sinonChai = require('sinon-chai')
import { PassThrough } from 'stream'
const expect = chai.expect
chai.use(sinonChai)

describe('profileImageUrlUpload', () => {
  const uploadProfileImageUrl = require('../../routes/profileImageUrlUpload')
  const challenges = require('../../data/datacache').challenges
  const security = require('../../lib/insecurity')
  let req: any
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    res = {
      status: sinon.stub().returnsThis(),
      json: sinon.spy(),
      location: sinon.stub().returnsThis(),
      redirect: sinon.spy()
    }
    req = {
      body: {},
      cookies: { token: 'testToken123' },
      headers: { host: 'juice-sh.op' }
    }
    next = sinon.spy()
    save = () => ({
      then () {}
    })
    const userMock = { data: { id: 42, email: 'test@juice-sh.op' } }
    security.authenticatedUsers.put('testToken123', userMock)

    const stream = new PassThrough()
    sinon.stub(require('request'), 'get').callsFake(() => {
      process.nextTick(() => {
        stream.emit('response', { statusCode: 200 })
      })
      return stream
    })
  })

  afterEach(() => {
    sinon.restore()
  })


  it('should solve "ssrfChallenge" if localhost was accessed', async () => {
    req.headers.host = '127.0.0.1'
    challenges.ssrfLocalChallenge = { solved: false, save }

    req.body.imageUrl = 'http://127.0.0.1/ftp/creds.jpg'

    await uploadProfileImageUrl()(req, res, next)

    expect(challenges.ssrfLocalChallenge.solved).to.equal(true)
  })
})

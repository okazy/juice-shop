/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function performRedirect () {
  return (req: Request, res: Response, next: NextFunction) => {
    const rawTo = req.query.to
    let toUrl: string | undefined

    if (typeof rawTo === 'string') {
      toUrl = rawTo
    } else if (Array.isArray(rawTo) && typeof rawTo[0] === 'string') {
      // If multiple "to" parameters are supplied, use the first one
      toUrl = rawTo[0]
    }

    if (!toUrl) {
      res.status(400)
      return next(new Error('Unrecognized target URL for redirect: ' + rawTo))
    }

    if (security.isRedirectAllowed(toUrl) && isLocalUrl(toUrl, req)) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6' })
      challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
      res.redirect(toUrl)
    } else {
      res.status(406)
      next(new Error('Unrecognized target URL for redirect: ' + toUrl))
    }
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}

function isLocalUrl (path: string, req: Request): boolean {
  // Treat root-relative paths within this application as local
  if (typeof path === 'string' && path.startsWith('/') && !path.startsWith('//')) {
    return true
  }

  try {
    const hostHeader = req.headers.host
    if (!hostHeader) {
      return false
    }
    const base = `${req.protocol}://${hostHeader}`
    const url = new URL(path, base)
    return url.origin === base
  } catch (e) {
    return false
  }
}

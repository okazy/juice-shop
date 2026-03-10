/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function getSafeImageExtension (rawUrl: string): string {
  const allowedExt = new Set(['jpg', 'jpeg', 'png', 'svg', 'gif'])

  try {
    const url = new URL(rawUrl)
    const pathname = url.pathname || ''
    const lastSegment = pathname.split('/').filter(Boolean).slice(-1)[0] || ''
    const dotIndex = lastSegment.lastIndexOf('.')
    if (dotIndex !== -1 && dotIndex < lastSegment.length - 1) {
      const candidate = lastSegment.slice(dotIndex + 1).toLowerCase()
      if (allowedExt.has(candidate)) {
        return candidate
      }
    }
  } catch {
    // ignore parsing errors and fall through to default
  }

  return 'jpg'
}

async function validateExternalUrl (rawUrl: string): Promise<URL> {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    throw new Error('Invalid URL')
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Unsupported URL protocol')
  }

  const lookup = dns.promises.lookup
  const addresses = await lookup(url.hostname, { all: true })

  const isPrivateOrLoopback = (address: string): boolean => {
    // IPv6 loopback or link-local
    if (address === '::1' || address.startsWith('fe80:') || address.startsWith('fc00:') || address.startsWith('fd00:')) {
      return true
    }

    const octets = address.split('.').map(Number)
    if (octets.length !== 4 || octets.some(o => Number.isNaN(o))) {
      return false
    }

    const [o1, o2] = octets
    // 10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
    if (o1 === 10 || o1 === 127) return true
    if (o1 === 192 && o2 === 168) return true
    if (o1 === 169 && o2 === 254) return true
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return true

    return false
  }

  for (const addr of addresses) {
    if (isPrivateOrLoopback(addr.address)) {
      throw new Error('URL resolves to a disallowed internal address')
    }
  }

  return url
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const rawUrl = req.body.imageUrl
      if (rawUrl.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const validatedUrl = await validateExternalUrl(rawUrl)
          const response = await fetch(validatedUrl.toString())
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = getSafeImageExtension(rawUrl)
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: rawUrl })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}

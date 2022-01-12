/**
 * originally from https://github.com/alipay/alipay-sdk-nodejs-all/blob/master/lib/antcertutil.ts
 */

import Hex from 'crypto-js/enc-hex'
import { padEnd } from 'lodash'
import Base64 from 'crypto-js/enc-base64'
import AES from 'crypto-js/aes'

const parseKey = (aesKey: string) => ({
  iv: Hex.parse(padEnd('', 32, '0')),
  key: Base64.parse(aesKey),
})

const aesEncrypt = (
  data: { [key: string]: string },
  aesKey: string
): string => {
  const { iv, key } = parseKey(aesKey)
  return AES.encrypt(JSON.stringify(data), key, { iv }).toString()
}

const aesDecrypt = (message: string, aesKey: string): string => {
  const { iv, key } = parseKey(aesKey)
  const bytes = AES.decrypt(message, key, {
    iv,
  })
  return JSON.parse(bytes.toString(CryptoJS.enc.Utf8))
}

export { aesDecrypt, aesEncrypt }

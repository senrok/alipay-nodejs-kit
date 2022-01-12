/**
 * originally from https://github.com/alipay/alipay-sdk-nodejs-all/blob/master/lib/antcertutil.ts
 */

import * as fs from 'fs'
import bignumber from 'bignumber.js'
import * as crypto from 'crypto'
import X509, { Certificate } from '@fidm/x509'

/** 从公钥证书文件里读取支付宝公钥 */
const loadPublicKeyFromPath = (filePath?: string): string => {
  if (!filePath) throw Error('empty file path')
  const fileData = fs.readFileSync(filePath)
  const certificate = X509.Certificate.fromPEM(fileData)
  return certificate.publicKeyRaw.toString('base64')
}

/** 从公钥证书内容或buffer读取支付宝公钥 */
const loadPublicKey = (content: string | Buffer): string => {
  const pemContent =
    typeof content === 'string' ? Buffer.from(content) : content
  const certificate = X509.Certificate.fromPEM(pemContent)
  return certificate.publicKeyRaw.toString('base64')
}

/** 从证书文件里读取序列号 */
const getSNFromPath = (filePath?: string, isRoot = false): string => {
  if (!filePath) throw Error('empty file path')
  const fileData = fs.readFileSync(filePath)
  return getSN(fileData, isRoot)
}

/** 从上传的证书内容或Buffer读取序列号 */
const getSN = (fileData: string | Buffer, isRoot = false): string => {
  const pemData =
    typeof fileData === 'string' ? Buffer.from(fileData) : fileData
  if (isRoot) {
    return getRootCertSN(pemData)
  }
  const certificate = X509.Certificate.fromPEM(pemData)
  return getCertSN(certificate)
}

/** 读取序列号 */
const getCertSN = (certificate: Certificate): string => {
  const { issuer, serialNumber } = certificate
  const principalName = issuer.attributes
    .reduceRight((prev, curr) => {
      const { shortName, value } = curr
      return `${prev}${shortName}=${value},`
    }, '')
    .slice(0, -1)
  const decimalNumber = new bignumber(serialNumber, 16).toString(10)
  return crypto
    .createHash('md5')
    .update(principalName + decimalNumber, 'utf8')
    .digest('hex')
}

/** 读取根证书序列号 */
const getRootCertSN = (rootContent: Buffer): string => {
  const certificates = X509.Certificate.fromPEMs(rootContent)
  let rootCertSN = ''
  certificates.forEach((item) => {
    if (item.signatureOID.startsWith('1.2.840.113549.1.1')) {
      const SN = getCertSN(item)
      if (rootCertSN.length === 0) {
        rootCertSN += SN
      } else {
        rootCertSN += `_${SN}`
      }
    }
  })
  return rootCertSN
}

// 格式化 key
const formatKey = (key: string, type: string): string => {
  const item = key.split('\n').map((val) => val.trim())

  // 删除包含 `RSA PRIVATE KEY / PUBLIC KEY` 等字样的第一行
  if (item[0].includes(type)) {
    item.shift()
  }

  // 删除包含 `RSA PRIVATE KEY / PUBLIC KEY` 等字样的最后一行
  if (item[item.length - 1].includes(type)) {
    item.pop()
  }

  return `-----BEGIN ${type}-----\n${item.join('')}\n-----END ${type}-----`
}

export { getSN, getSNFromPath, loadPublicKeyFromPath, loadPublicKey, formatKey }

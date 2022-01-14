/**
 * originally from https://github.com/alipay/alipay-sdk-nodejs-all/blob/master/lib/util.ts
 */

import snakeCaseKeys from 'snakecase-keys'
import { SDKConfig } from '../config'
import crypto from 'crypto'
import * as iconv from 'iconv-lite'
import { aesEncrypt } from './aes'

const ALIPAY_ALGORITHM_MAPPING: Record<'RSA' | 'RSA2', string> = {
  RSA: 'RSA-SHA1',
  RSA2: 'RSA-SHA256',
}

type SignParams = {
  needEncrypt?: boolean
}

/**
 * 签名
 * @description https://opendocs.alipay.com/common/02kf5q
 * @param {string} method 调用接口方法名，比如 alipay.ebpp.bill.add
 * @param {object} bizContent 业务请求参数
 * @param {object} publicArgs 公共请求参数
 * @param {object} config sdk 配置
 */
const sign = (
  method: string,
  {
    bizContent,
    needEncrypt,
    ...restParams
  }: SignParams & { bizContent?: { [key: string]: string } },
  {
    appId,
    charset,
    version,
    signType,
    appCertSn,
    alipayCertSn,
    wsServiceUrl,
    encryptKey,
    privateKey,
  }: SDKConfig
): { [key: string]: string } & { sign: string; bizContent?: string } => {
  const params: { [key: string]: string | undefined } = {
    ...restParams,
    appId,
    charset,
    version,
    signType,
    appCertSn,
    alipayCertSn,
    wsServiceUrl,
  }

  if (bizContent) {
    if (needEncrypt) {
      if (!encryptKey) {
        throw new Error('please the encrypt key')
      }
      params['encryptType'] = 'AES'
      params['bizContent'] = aesEncrypt(snakeCaseKeys(bizContent), encryptKey)
    } else {
      params['bizContent'] = JSON.stringify(snakeCaseKeys(bizContent))
    }
  }

  // params key 驼峰转下划线
  const decamelizeParams = snakeCaseKeys(params)

  // 排序
  const signStr = Object.keys(decamelizeParams)
    .sort()
    .map((key) => {
      let data = decamelizeParams[key]
      if (typeof data !== 'string') {
        data = JSON.stringify(data)
      }
      return `${key}=${iconv.encode(data, charset)}`
    })
    .join('&')

  const sign = crypto
    .createSign(ALIPAY_ALGORITHM_MAPPING[signType])
    .update(signStr, 'utf8')
    .sign(privateKey, 'base64')

  return { ...decamelizeParams, sign }
}

/**
 *
 * @param originStr 开放平台返回的原始字符串
 * @param responseKey xx_response 方法名 key
 */
const getSignStr = (originStr: string, responseKey: string): string => {
  // 待签名的字符串
  let validateStr = originStr.trim()
  // 找到 xxx_response 开始的位置
  const startIndex = originStr.indexOf(`${responseKey}"`)
  // 找到最后一个 “"sign"” 字符串的位置（避免）
  const lastIndex = originStr.lastIndexOf('"sign"')

  /**
   * 删除 xxx_response 及之前的字符串
   * 假设原始字符串为
   *  {"xxx_response":{"code":"10000"},"sign":"jumSvxTKwn24G5sAIN"}
   * 删除后变为
   *  :{"code":"10000"},"sign":"jumSvxTKwn24G5sAIN"}
   */
  validateStr = validateStr.substr(startIndex + responseKey.length + 1)

  /**
   * 删除最后一个 "sign" 及之后的字符串
   * 删除后变为
   *  :{"code":"10000"},
   * {} 之间就是待验签的字符串
   */
  validateStr = validateStr.substr(0, lastIndex)

  // 删除第一个 { 之前的任何字符
  validateStr = validateStr.replace(/^[^{]*{/g, '{')

  // 删除最后一个 } 之后的任何字符
  validateStr = validateStr.replace(/\}([^}]*)$/g, '}')

  return validateStr
}

// 结果验签
const checkResponseSign = (
  signStr: string,
  responseKey: string,
  alipayPublicKey: string,
  signType: 'RSA' | 'RSA2'
): boolean => {
  // 带验签的参数不存在时返回失败
  if (!signStr) {
    return false
  }

  // 根据服务端返回的结果截取需要验签的目标字符串
  const validateStr = getSignStr(signStr, responseKey)
  // 服务端返回的签名
  const serverSign = JSON.parse(signStr).sign

  // 参数存在，并且是正常的结果（不包含 sub_code）时才验签
  const verifier = crypto.createVerify(ALIPAY_ALGORITHM_MAPPING[signType])
  verifier.update(validateStr, 'utf8')

  return verifier.verify(alipayPublicKey, serverSign, 'base64')
}

export { sign, ALIPAY_ALGORITHM_MAPPING, checkResponseSign }

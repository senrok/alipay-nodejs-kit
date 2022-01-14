import { SDKConfig } from './config'
import {
  formatKey,
  getSN,
  getSNFromPath,
  loadPublicKey,
  loadPublicKeyFromPath,
} from './util/cert'
import { checkResponseSign, sign } from './util/sign'
import axios from 'axios'
import * as url from 'url'
import { aesDecrypt } from './util/aes'
import camelcaseKeys from 'camelcase-keys'

export interface IResult {
  code: string
  msg: string
  sub_code?: string
  sub_msg?: string
  [key: string]: any
}

export interface IRequestParams {
  [key: string]: any
  bizContent?: any
  // 自动AES加解密
  needEncrypt?: boolean
}

export interface IRequestOption {
  validateSign?: boolean
  log?: {
    info(...args: any[]): any
    error(...args: any[]): any
  }
}

export class Alipay {
  public config: SDKConfig & Pick<Required<SDKConfig>, 'gateway'>

  constructor(config: SDKConfig) {
    if (!config.appId) {
      throw Error('config.appId is required')
    }
    if (!config.privateKey) {
      throw Error('config.privateKey is required')
    }

    const privateKeyType =
      config.keyType === 'PKCS8' ? 'PRIVATE KEY' : 'RSA PRIVATE KEY'
    config.privateKey = formatKey(config.privateKey, privateKeyType)
    // 普通公钥模式和证书模式二选其一，传入了证书路径或内容认为是证书模式
    if (config.appCertPath || config.appCertContent) {
      // 证书模式，优先处理传入了证书内容的情况，其次处理传入证书文件路径的情况
      // 应用公钥证书序列号提取
      config.appCertSn = !config.appCertContent
        ? getSNFromPath(config.appCertPath, false)
        : getSN(config.appCertContent, false)
      // 支付宝公钥证书序列号提取
      config.alipayCertSn = !config.alipayPublicCertContent
        ? getSNFromPath(config.alipayPublicCertPath, false)
        : getSN(config.alipayPublicCertContent, false)
      // 支付宝根证书序列号提取
      config.alipayRootCertSn = !config.alipayRootCertContent
        ? getSNFromPath(config.alipayRootCertPath, true)
        : getSN(config.alipayRootCertContent, true)
      config.alipayPublicKey = !config.alipayPublicCertContent
        ? loadPublicKeyFromPath(config.alipayPublicCertPath)
        : loadPublicKey(config.alipayPublicCertContent)
      config.alipayPublicKey = formatKey(config.alipayPublicKey, 'PUBLIC KEY')
    } else if (config.alipayPublicKey) {
      // 普通公钥模式，传入了支付宝公钥
      config.alipayPublicKey = formatKey(config.alipayPublicKey, 'PUBLIC KEY')
    }
    this.config = {
      gateway: 'https://openapi.alipay.com/gateway.do',
      timeout: 5000,
      camelcase: true,
      version: '1.0',
      ...config,
    }
  }

  async exec<T>(
    method: string,
    params: IRequestParams = {},
    option: IRequestOption = {}
  ): Promise<IResult & T> {
    // return new Result({})
    const cfg = this.config
    const signData = sign(method, params, cfg)
    return new Promise((resolve, reject) => {
      axios
        .post(cfg.gateway, new url.URLSearchParams(signData).toString())
        .then((resp) => {
          let data = resp.data
          let responseKey
          if (resp.status == 200) {
            try {
              responseKey = `${method.replace(/\./g, '_')}_response`
              resp.data = resp.data[responseKey]
            } catch (e) {
              return reject({
                serverResult: resp.data,
                errorMessage: '[AlipaySdk]Response 格式错误',
              })
            }
            if (data) {
              if (params.needEncrypt) {
                data = aesDecrypt(data, cfg.encryptKey ?? '')
              }

              // 按字符串验签
              const validateSuccess =
                option.validateSign &&
                cfg.alipayPublicKey &&
                cfg.alipayPublicKey != ''
                  ? checkResponseSign(
                      JSON.stringify(data),
                      responseKey,
                      cfg.alipayPublicKey,
                      cfg.signType
                    )
                  : true

              if (validateSuccess) {
                return resolve(
                  cfg.camelcase ? camelcaseKeys(data, { deep: true }) : data
                )
              }
              return reject({
                serverResult: data,
                errorMessage: '[AlipaySdk]验签失败',
              })
            }
          } else {
          }
        })
        .catch((e) => {
          return reject({
            serverResult: e,
            errorMessage: '[AlipaySdk]HTTP 请求错误',
          })
        })
    })
  }
}

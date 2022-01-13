import { SDKConfig } from './config'
import {
  formatKey,
  getSN,
  getSNFromPath,
  loadPublicKey,
  loadPublicKeyFromPath,
} from './util/cert'

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
  public config: SDKConfig

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
  ): Promise<Result<T, Error>> {
    // return new Result({})
  }
}

<?php

namespace ZUtilitys\WechatEncrypt;

/**
 * 微信数据加密
 * Class WechatEncrypt
 */
class WechatEncrypt
{
    protected $appMsgToken;
    protected $encodingAseKey;
    protected $appId;

    public function __construct($appMsgToken, $encodingAseKey, $appId)
    {
        $this->appMsgToken = $appMsgToken;
        $this->encodingAseKey = $encodingAseKey;
        $this->appId = $appId;
    }

    /**
     * url参数签名校验
     * @param $signature
     * @param $timestamp
     * @param $nonce
     * @return bool
     */
    public function checkSignature($signature, $timestamp, $nonce)
    {
        $arr = [$this->appMsgToken, $timestamp, $nonce];
        sort($arr, SORT_STRING);
        $str = sha1(implode('', $arr));

        if ($str === $signature) {
            return true;
        }

        return false;
    }

    /**
     * 基于PKCS7算法的加密
     * @param $msg
     * @return string
     */
    public function encryptMsg($msg)
    {
        $key = base64_decode($this->encodingAseKey . '=');
        $randomStr = $this->getRandomStr();
        $text = $randomStr . pack("N", strlen($msg)) . $msg . $this->appId;
        $iv = substr($key, 0, 16);

        // 对需要加密的明文进行填充补位
        $block_size = 32;
        $text_length = strlen($text);
        //计算需要填充的位数
        $amount_to_pad = $block_size - ($text_length % $block_size);
        if ($amount_to_pad == 0) {
            $amount_to_pad = $block_size;
        }
        //获得补位所用的字符
        $pad_chr = chr($amount_to_pad);
        $tmp = '';
        for ($index = 0; $index < $amount_to_pad; $index++) {
            $tmp .= $pad_chr;
        }
        $text .= $tmp;

        $encrypted = openssl_encrypt($text, 'AES-256-CBC', $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);
        $encryptMsg = base64_encode($encrypted);

        return $encryptMsg;
    }

    /**
     * 基于PKCS7算法的解密
     * @param $encryptData
     * @return array
     */
    public function decryptMsg($encryptData)
    {
        $key = base64_decode(self::ENCODING_AES_KEY. '=');
        $iv = substr($key, 0, 16);
        //openssl解密
        $decrypted = openssl_decrypt(base64_decode($encryptData), 'AES-256-CBC', $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);
        //对解密后的明文进行补位删除
        $pad = ord(substr($decrypted, -1));
        if ($pad < 1 || $pad > 32) {
            $pad = 0;
        }
        $rst = substr($decrypted, 0, (strlen($decrypted) - $pad));
        if (strlen($rst) < 16) {
            return [3, 'content is empty'];
        }

        $content = substr($rst, 16, strlen($rst));
        $len_list = unpack("N", substr($content, 0, 4));
        $xml_len = $len_list[1];
        $msg = substr($content, 4, $xml_len);

        return [0, $msg];
    }

    /**
     * 加密消息签名
     * @param $encryptData
     * @param $timestamp
     * @param $nonce
     * @return string
     */
    public function msgSign($encryptData, $timestamp, $nonce)
    {
        $arr = [$encryptData, $this->appMsgToken, $timestamp, $nonce];
        sort($arr, SORT_STRING);
        return sha1(implode($arr));
    }

    /**
     * 获取随机16位字符串
     * @return string
     */
    private function getRandomStr()
    {
        $str = '';
        $str_pol = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz';
        $max = strlen($str_pol) - 1;
        for ($i = 0; $i < 16; $i++) {
            $str .= $str_pol[mt_rand(0, $max)];
        }
        return $str;
    }
}
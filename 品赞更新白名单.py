# cron 10 2
# new Env('更新IP代理白名单');

import requests
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import time
import json

# --- 配置区域 ---
# 品赞代理配置
PINZAN_API_URL = 'https://service.ipzan.com/whiteList-add'  # 官方API地址
PINZAN_NO = '20241212334904497725'  # 套餐购买编号
PINZAN_SIGN_KEY = '770tbbbbc27ppmoj'  # 签名密钥（控制台查看）
PINZAN_LOGIN_PASSWORD = 'ccov2001'  # 登录密码
PINZAN_PACKAGE_SECRET = 'pvtov1rp39ndkbo'  # 套餐提取密匙
PINZAN_USER_ID = 'DDF84L9UAAO'  # 品赞用户ID

# --- 日志配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_current_ip():
    """获取本机公网IP地址"""
    try:
        response = requests.get('https://myip.ipip.net/json', timeout=10)
        response.raise_for_status()
        data = response.json()
        ip = data.get('data', {}).get('ip')
        if not ip:
            raise ValueError("未能从API响应中获取IP地址")
        return ip
    except (requests.RequestException, ValueError) as e:
        logging.error(f"获取IP地址失败: {e}")
        return None

def get_pinzan_sign(login_password, package_secret, sign_key):
    """生成品赞API签名"""
    try:
        ts = int(time.time())
        sign_content = f"{login_password}:{package_secret}:{ts}"
        key = sign_key.encode('utf-8')
        
        logging.info(f"签名内容: {sign_content}")
        logging.info(f"签名密钥: {sign_key}")
        logging.info(f"密钥长度: {len(key)} 字节")
        logging.info(f"时间戳: {ts}")
        
        cipher = AES.new(key, AES.MODE_ECB)
        padded = pad(sign_content.encode('utf-8'), AES.block_size, style='pkcs7')
        encrypted = cipher.encrypt(padded)
        sign = binascii.hexlify(encrypted).decode('utf-8')
        
        logging.info(f"生成的签名: {sign}")
        return sign, ts
    except Exception as e:
        logging.error(f"生成签名失败: {e}")
        return None, None

def get_pinzan_white_list(user_id, no):
    """获取品赞代理的IP白名单"""
    if not (user_id and no):
        logging.warning("获取白名单参数未配置完整，跳过获取。")
        return []
    try:
        api_url = "https://service.ipzan.com/whiteList-get"
        params = {
            'userId': user_id,
            'no': no
        }
        logging.info(f"正在请求白名单API: {api_url}")
        logging.info(f"请求参数: {params}")
        response = requests.get(api_url, params=params, timeout=10)
        logging.info(f"API响应状态码: {response.status_code}")
        logging.info(f"API响应内容: {response.text}")
        response.raise_for_status()
        try:
            data = response.json()
            logging.info(f"解析的JSON数据: {data}")
            if isinstance(data, dict) and 'data' in data:
                return data['data']
            elif isinstance(data, list):
                return data
            else:
                logging.warning(f"白名单API响应格式异常: {response.text}")
                return []
        except json.JSONDecodeError as e:
            logging.warning(f"白名单API响应不是JSON格式: {response.text}")
            logging.warning(f"JSON解析错误: {e}")
            return []
    except Exception as e:
        logging.error(f"获取白名单失败: {e}")
        return []

def delete_pinzan_white_list(ip, user_id, no):
    """
    删除品赞代理的IP白名单 - 简化版，不需要签名
    """
    if not (ip and user_id and no):
        logging.warning("删除白名单参数未配置完整，跳过删除。")
        return "跳过"
    
    try:
        api_url = "https://service.ipzan.com/whiteList-del"
        params = {
            'ip': ip,
            'userId': user_id,
            'no': no
        }
        
        logging.info(f"删除API请求URL: {api_url}")
        logging.info(f"删除API请求参数: {params}")
        
        response = requests.get(api_url, params=params, timeout=10)
        logging.info(f"删除API响应状态码: {response.status_code}")
        logging.info(f"删除API响应内容: {response.text}")
        
        response.raise_for_status()
        return response.text
    except Exception as e:
        logging.error(f"删除请求出错: {e}")
        return f"请求出错: {e}"

def add_pinzan_white_list(ip, no, sign_key, login_password, package_secret):
    """
    添加品赞代理的IP白名单
    """
    if not (ip and no and sign_key and login_password and package_secret):
        logging.warning("添加白名单参数未配置完整，跳过添加。")
        return "跳过"
    
    try:
        sign, ts = get_pinzan_sign(login_password, package_secret, sign_key)
        if not sign:
            return "签名生成失败"
        
        api_url = "https://service.ipzan.com/whiteList-add"
        params = {
            'ip': ip,
            'no': no,
            'sign': sign
        }
        
        logging.info(f"添加API请求URL: {api_url}")
        logging.info(f"添加API请求参数: {params}")
        
        response = requests.get(api_url, params=params, timeout=10)
        logging.info(f"添加API响应状态码: {response.status_code}")
        logging.info(f"添加API响应内容: {response.text}")
        
        response.raise_for_status()
        return response.text
    except Exception as e:
        logging.error(f"添加请求出错: {e}")
        return f"请求出错: {e}"

def main():
    ip = get_current_ip()
    if not ip:
        logging.error("无法获取当前IP，程序终止。")
        return
    logging.info(f"获取到当前公网IP: {ip}")

    # 1. 获取现有白名单
    logging.info("正在获取现有白名单...")
    existing_ips = get_pinzan_white_list(PINZAN_USER_ID, PINZAN_NO)
    
    if existing_ips:
        logging.info(f"发现现有白名单IP: {existing_ips}")
        
        # 2. 删除所有旧的白名单IP（包括当前IP，因为我们要重新添加）
        for old_ip in existing_ips:
            ip_to_del = old_ip['id'] if isinstance(old_ip, dict) and 'id' in old_ip else old_ip
            logging.info(f"正在删除IP: {ip_to_del}")
            result_del = delete_pinzan_white_list(ip_to_del, PINZAN_USER_ID, PINZAN_NO)
            logging.info(f"删除IP {ip_to_del} 结果: {result_del}")
            time.sleep(1)  # 防止访问频率过快
    else:
        logging.info("未发现现有白名单或获取失败")

    # 3. 添加当前IP到白名单
    logging.info(f"正在添加当前IP到白名单: {ip}")
    result_add = add_pinzan_white_list(ip, PINZAN_NO, PINZAN_SIGN_KEY, PINZAN_LOGIN_PASSWORD, PINZAN_PACKAGE_SECRET)
    logging.info(f"添加品赞白名单结果: {result_add}")

if __name__ == "__main__":
    main()

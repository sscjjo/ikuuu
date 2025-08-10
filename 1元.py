import requests
import logging

# 日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 配置区
LOGIN_URL = 'https://ikuuu.de/auth/login'
CHECKIN_URL = 'https://ikuuu.de/user/checkin'
EMAIL = '26407964@qq.com'
PASSWORD = 'ccov2001'

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Origin': 'https://ikuuu.ch',
    'Referer': 'https://ikuuu.ch/auth/login',
}

def login_and_get_cookies(email, password):
    """登录并返回cookies"""
    session = requests.Session()
    data = {
        'email': email,
        'passwd': password,
        'code': ''
    }
    try:
        resp = session.post(LOGIN_URL, data=data, headers=headers, timeout=10)
        resp.raise_for_status()
        if resp.json().get('ret') == 1:
            logging.info('登录成功')
            return session
        else:
            logging.error(f"登录失败: {resp.json().get('msg')}")
            return None
    except Exception as e:
        logging.error(f"登录请求异常: {e}")
        return None

def checkin(session):
    """签到"""
    try:
        resp = session.post(CHECKIN_URL, headers=headers, timeout=10)
        resp.raise_for_status()
        result = resp.json()
        if result.get('ret') == 1:
            logging.info(f"签到成功: {result.get('msg')}")
        else:
            logging.warning(f"签到失败: {result.get('msg')}")
    except Exception as e:
        logging.error(f"签到请求异常: {e}")

def main():
    session = login_and_get_cookies(EMAIL, PASSWORD)
    if session:
        checkin(session)
    else:
        logging.error('未能获取有效登录会话，签到终止。')

if __name__ == '__main__':
    main() 

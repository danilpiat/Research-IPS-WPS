import time

from scapy.layers.eap import *
from scapy.all import *
from scapy.layers.inet import *
from scapy import *
from datetime import date, timedelta
import requests
from selenium import webdriver
from seleniumwire import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.utils import ChromeType
import getpass
import keyring

if sys.platform == 'win32':
    import wmi
else:
    pass

array_captured_packet = []
mac_list = []

global rlogint,rpasst

def wps_logging(captured_packet):
    today_date = date.today()
    yesterday_date = date.today() - timedelta(days=1)
    current_directory = os.getcwd()
    files = os.listdir(current_directory)
    if "WPS Logs" not in files:
        os.mkdir(current_directory + "/WPS Logs")
    wps_logs = current_directory + "/WPS Logs"
    for log_files in os.listdir(wps_logs):
        if log_files.find(str(today_date)) != -1 or log_files.find(str(yesterday_date)) != -1:
            pass
        else:
            os.remove(wps_logs + '/' + log_files)
    pktdump = PcapWriter(wps_logs + '/wps_logs_' + str(today_date) + '.pcap', append=True, sync=True)
    pktdump.write(captured_packet)
    # with open(wps_logs+'/wps_logs_'+str(today_date)+'.pcap', 'a') as f:
    #         f.write(captured_packet)


def mac_blacklist(captured_packet):
    mac_list.append(captured_packet)
    blacklist = []
    unique_mac = set(mac_list)
    for mac in unique_mac:
        blacklist.append(mac)
    return blacklist


def eap_output(captured_packet):
    if captured_packet.haslayer(EAP):
        wps_logging(captured_packet)
        array_captured_packet.append(captured_packet)
        if len(array_captured_packet) > 40:
            print("WPS Bruteforce Detect")
            wps_bruteforce_attack(captured_packet)
            if captured_packet[EAP].code == 2:
                mac_list_pd = mac_blacklist(captured_packet[Ether].src)
                add_to_filter(mac_list_pd)

            # captured_packet = redirect_to_lan_interface("WPS Bruteforce")
            # sendp(captured_packet, iface="enp9s0")
            # blacklist_mac.append(captured_packet.Ether().src)
        else:
            pass
            # captured_packet = redirect_to_lan_interface("All is good")
            # sendp(captured_packet, iface="enp9s0")

        if 12 < len(array_captured_packet) < 40:
            print("WPS Pixie Dust Detect")
            wps_pixiedust_attack(captured_packet)
            if captured_packet[EAP].code == 2:
                mac_list_bf = mac_blacklist(captured_packet[Ether].src)
                add_to_filter(mac_list_bf)
            # captured_packet = redirect_to_lan_interface("WPS Pixie Dust")
            # sendp(captured_packet, iface="enp9s0")
            # blacklist_mac.append(captured_packet.Ether().src)
        else:
            pass
            # captured_packet = redirect_to_lan_interface("All is good")
            # sendp(captured_packet, iface="enp9s0")

        return captured_packet.command()


def wps_bruteforce_attack(cp, true=None):
    cp_str = str(cp)
    if '\\x01' in cp_str:
        return true


def wps_pixiedust_attack(cp, true=None):
    cp_str = str(cp)
    if '\\x007*' in cp_str:
        return true


def redirect_to_lan_interface(alertmassage):
    if alertmassage == "WPS Bruteforce":
        capture_packet_bad = Ether() / IP(dst="192.168.1.33") / UDP(sport=9090, dport=9090) / Raw(load=(alertmassage))
        return capture_packet_bad
    else:
        capture_packet_good = Ether() / IP(dst="192.168.1.33") / UDP(sport=9090, dport=9090) / Raw(load=(alertmassage))
        return capture_packet_good


def packets_counter(packets):
    len(packets)
    for i in range(len(packets)):
        if i > 8:
            print("Looks like there is hacker somewhere")


def iface_config_linux():
    interfaces = []
    system_interfaces = os.popen("ifconfig | grep \": \" | cut -d  \":\" -f 1").read()
    for line in system_interfaces.split("\n"):
        if line != "":
            interfaces.append(line)
    ws_iface = list(filter(lambda x: 'wl' in x, interfaces))
    return ws_iface


def get_default_gateway_linux():
    with open("/proc/net/route") as f_h:
        for line in f_h:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return inet_ntoa(struct.pack("<L", int(fields[2], 16)))


def get_default_gateway_win32():
    wmi_obj = wmi.WMI()
    wmi_sql = "select DefaultIPGateway from Win32_NetworkAdapterConfiguration where IPEnabled=TRUE"
    wmi_out = wmi_obj.query(wmi_sql)
    return wmi_out[0].DefaultIPGateway[0]


if sys.platform == 'win32':
    router_ip = get_default_gateway_win32()
else:
    router_ip = get_default_gateway_linux()
auth_token = 'JSESSIONID=59d982b3263e31a84de08a2aba1ed7'


# def logout(session_id):
#     r = requests.get(router_ip + '/' + session_id + '/userRpm/LogoutRpm.htm',
#                      headers={'Referer': router_ip + '/' + session_id + '/userRpm/MenuRpm.htm', 'Cookie': auth_token})
#     if r.status_code == 200:
#         return 'Loging out: ' + str(r.status_code)
#     else:
#         return 'Unable to logout'


# def login():
#     r = requests.get(router_ip + '/userRpm/LoginRpm.htm?Save=Save',
#                      headers={'Referer': router_ip + '/', 'Cookie': auth_token})
#
#     if r.status_code == 200:
#         x = 1
#         while x < 3:
#             try:
#                 session_id = r.text[r.text.index(router_ip) + len(router_ip) + 1:r.text.index('userRpm') - 1]
#                 return session_id
#                 break
#
#             except ValueError:
#                 return 'Login error'
#
#             x += 1
#     else:
#         return 'IP unreachable'


def login(browser):
    try:
        rlogin = WebDriverWait(browser, 50).until(ec.element_to_be_clickable((By.XPATH, '//*[@id="userName"]')))
        rlogin.click()
        rlogin.send_keys(rlogint)
        time.sleep(0.3)
    except:
        print('Something with login')
    try:
        rpass = WebDriverWait(browser, 50).until(ec.element_to_be_clickable((By.XPATH, '//*[@id="pcPassword"]')))
        rpass.click()
        rpass.send_keys(keyring.get_password(systemname, rlogint))
        time.sleep(0.3)
        rpass.send_keys(Keys.ENTER)
    except:
        print('Something with password')
    return True


def add_to_filter(mac_addr):
    # systemname = 'IPS'
    # rlogint = input("Введите логин от веб-интерфейса: ")
    # rpasst = getpass.getpass(prompt="Введите пароль от веб-интерфейса: ")
    # try:
    #     keyring.set_password(systemname, rlogint, rpasst)
    # except Exception as error:
    #     print('Error: {}'.format(error))
    browser = webdriver.Chrome(service=Service(ChromeDriverManager(chrome_type=ChromeType.CHROMIUM).install()))
    # options = Options()
    # options.add_argument('--headless')
    # options.add_argument('--disable-gpu')
    options = webdriver.ChromeOptions()
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    options.add_argument('--remote-debugging-port=9222')
    # browser = webdriver.Chrome(executable_path=r'/home/danil/Загрузки/chromedriver_linux64/chromedriver',
    #                            options=options)
    browser.get('http://' + str(router_ip))
    login(browser)
    browser.switch_to.frame('bottomLeftFrame')
    openmenu = WebDriverWait(browser, 50).until(ec.element_to_be_clickable((By.XPATH, ('//*[@id="menu_wl"]'))))
    openmenu.click()
    time.sleep(0.5)
    selectfiltering = WebDriverWait(browser, 50).until(ec.element_to_be_clickable((By.XPATH, '//*[@id="menu_wlacl"]')))
    selectfiltering.click()
    time.sleep(0.5)
    browser.switch_to.default_content()
    browser.switch_to.frame('mainFrame')
    is_off = 1
    if is_off == 1:
        is_on = browser.find_elements(By.XPATH, '//*[@id="acl_disabled"]')
        if 'Отключено' in is_on[0].text:
            turnfiltering = WebDriverWait(browser, 50).until(
                ec.element_to_be_clickable((By.XPATH, '//*[@id="acl_en"]')))
            turnfiltering.click()
            is_off = 0
            time.sleep(25)
    time.sleep(1)
    for mac in mac_addr:
        print(mac)
        addmac = WebDriverWait(browser, 50).until(
            ec.element_to_be_clickable((By.XPATH, '//*[@id="main"]/div/div/p[9]/input[1]')))
        addmac.click()
        time.sleep(0.5)
        instertmac = WebDriverWait(browser, 50).until(
            ec.element_to_be_clickable((By.XPATH, '//*[@id="MAC"]')))
        instertmac.click()
        time.sleep(0.5)
        instertmac.send_keys(mac)
        insterttext = WebDriverWait(browser, 50).until(
            ec.element_to_be_clickable((By.XPATH, '//*[@id="desc"]')))
        insterttext.click()
        time.sleep(0.5)
        insterttext.send_keys("Hacker")
        savebtn = WebDriverWait(browser, 50).until(
            ec.element_to_be_clickable((By.XPATH, '//*[@id="main"]/div/p[4]/input[1]')))
        savebtn.click()
        time.sleep(2)
    logout(browser)


def logout(browser):
    browser.switch_to.default_content()
    browser.switch_to.frame('bottomLeftFrame')
    try:
        rlogout = WebDriverWait(browser, 50).until(ec.element_to_be_clickable((By.XPATH, '//*[@id="menu_logout"]')))
        rlogout.click()
    except:
        print('Something with logout')


def main():
    if sys.platform == 'win32':
        packets = sniff(prn=eap_output)
    else:
        packets = sniff(iface=iface_config_linux()[0], prn=eap_output)
    packets_counter(packets)


if __name__ == '__main__':
    systemname = 'IPS'
    rlogint = input("Введите логин от веб-интерфейса: ")
    rpasst = getpass.getpass(prompt="Введите пароль от веб-интерфейса: ")
    try:
        keyring.set_password(systemname, rlogint, rpasst)
    except Exception as error:
        print('Error: {}'.format(error))
    main()

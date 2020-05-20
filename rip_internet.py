import requests
from bs4 import BeautifulSoup
import pprint
import random
import json

#GLOBAL VARIABLES THAT NEED CHANGING
openwrt_ip = '192.168.1.1'
username = '<openwrt_username>'
password = '<openwrt_password>'

#actual code starting now
sess = requests.Session()
def doLogin():
    loginFormData = {
        'luci_username' : username,
        'luci_password' : password
    }
    
    loginResponse = sess.post('http://{}/cgi-bin/luci'.format(openwrt_ip), data = loginFormData)
    #print(loginResponse.cookies)

def getAllRules():
    rules = []
    
    rulesResponse = sess.get('http://{}/cgi-bin/luci/admin/network/firewall/rules'.format(openwrt_ip))

    soup = BeautifulSoup(rulesResponse.text, features="html.parser")
    ruleDivs = soup.find_all('div', ['tr', 'cbi-section-table-row'])
    for ruleDiv in ruleDivs:
        ruleName = ''
        ruleEnabled = True
        ruleIds = []

        #trying to get the rule name
        try:
            ruleName = ruleDiv['data-title']
        except KeyError:
            continue
        
        try:
            ruleStatusInput = soup.find('div', {'data-title' : ruleName}).find('input', {'type' : 'checkbox' })
            checkedStatus = ruleStatusInput['checked']

            ruleEnabled = True
        except KeyError:
            ruleEnabled = False
        except TypeError:
            continue
        
        ruleInputs = soup.find('div', {'data-title' : ruleName}).find_all('input', {'name' : True, 'type' : ['checkbox', 'hidden']})
        for ruleInput in ruleInputs:
            if 'enabled' in ruleInput.get('name'):        
                ruleIds.append(ruleInput.get('name'))

        rules.append({
            'name' : ruleName,
            'enabled' : ruleEnabled,
            'ids' : ruleIds
        })
  
    return rules
        
def ruleIsEnabled(ruleName):
    rulesResponse = sess.get('http://{}/cgi-bin/luci/admin/network/firewall/rules'.format(openwrt_ip))

    soup = BeautifulSoup(rulesResponse.text, features="html.parser")
    ruleStatusInput = soup.find('div', {'data-title' : ruleName}).find('input', {'type' : 'checkbox' })
    try:
        checkedStatus = ruleStatusInput['checked']
        print("Rule is enabled")

        return True
    except KeyError or TypeError:
        print("Rule is not enabled")
        return False


def getIdOfRule(ruleName):
    rulesResponse = sess.get('http://{}/cgi-bin/luci/admin/network/firewall/rules'.format(openwrt_ip))

    soup = BeautifulSoup(rulesResponse.text, features="html.parser")
    ruleInputs = soup.find('div', {'data-title' : ruleName}).find_all('input', {'name' : True, 'type' : ['checkbox', 'hidden']})

    validIds = []
    for ruleInput in ruleInputs:
        if 'enabled' in ruleInput.get('name'):        
            print("id of rule is {}".format(ruleInput.get('name')))
            validIds.append(ruleInput.get('name'))

    return validIds

def saveAndApplyChanges(token):
    rollbackParams = {
        'sid' : sess.cookies['sysauth'],
        'token' : token,
        '_' : random.random()
    }

    pprint.pprint(rollbackParams)
    rollbackResponse = sess.post('http://{}/cgi-bin/luci/admin/uci/apply_rollback'.format(openwrt_ip), params = rollbackParams)
    print ('Got {} from rollback'.format(rollbackResponse.text))
    if len(rollbackResponse.text) == 0:
        print('Error while trying to save and apply changes')
        return
    
    rollbackToken = json.loads(rollbackResponse.text)

    confirmParams = {
        'token' : rollbackToken['token'],
        '_' : random.random()
    }
    
    confirmResponse = sess.post('http://{}/cgi-bin/luci/admin/uci/confirm'.format(openwrt_ip), params = confirmParams)
    print('Confirm Status = {}'.format(confirmResponse.status_code))
    print('Confirm Response = {}'.format(confirmResponse.text))
    
def toggleRule(ruleName):
    rulesResponse = sess.get('http://{}/cgi-bin/luci/admin/network/firewall/rules'.format(openwrt_ip))

    #building the form request data, need the current rules values/status
    formData = {}
    soup = BeautifulSoup(rulesResponse.text, features="html.parser")
    form = soup.find('form')
    for ruleInput in form.find_all('input'):
        if ruleInput.get('type') not in ['button', 'submit'] and ruleInput.get('name') not in [None]:
            formData[ruleInput.get('name')] = ruleInput.get('value')

    for selectRuleInput in form.find_all('select'):
        for selectOption in selectRuleInput.find_all('option'):
            if selectOption.get('selected') == 'selected':
                formData[selectRuleInput.get('name')] = selectOption.get('value')
                break

    #needed to force to apply changes now
    #this is hardcoded to complete the form, no clue why
    formData['cbi.apply'] = 1
    formData['_newopen.proto'] = 'tcp udp'

    #toggling the rule
    ruleIds = getIdOfRule(ruleName)
    for ruleId in ruleIds:
        if ruleId.startswith('cbid') and ruleIsEnabled(ruleName):
            formData.pop(ruleId, None)

    rules = getAllRules()
    for rule in rules:
        if not rule['enabled'] and rule['name'] != ruleName:
            for ruleId in rule['ids']:
                if ruleId.startswith('cbid'):
                    formData.pop(ruleId, None)
                    
    pprint.pprint(formData)

    toggleResponse = sess.post('http://{}/cgi-bin/luci/admin/network/firewall/rules'.format(openwrt_ip), files = formData)
    print(toggleResponse.status_code)

    saveAndApplyChanges(formData['token'])
      
if __name__ == '__main__':
    doLogin()
    ruleIsEnabled('DropThatTV')
    #toggleRule('BlockHisPhone')
    

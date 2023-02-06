from evtx_reader import *
import xml.etree.ElementTree as ET
from txt_reader import search

# https://attack.mitre.org/techniques/T1087/
def rule1_user_enumeration(filename):
    ret = parse_evtx_to_xml(filename)
    dump_xmlstr_to_file(ret, r'test/resources/rule1.xml')
    xmltree = ET.parse(r'test/resources/rule1.xml')
    xmlroot = xmltree.getroot()

    alert = False
    eventid4688 = False
    for x in range(len(xmlroot)):
        for y in xmlroot[x]:
            if 'System' in y.tag:
                for z in y:
                    if 'EventID' in z.tag:
                        if z.text == '4688':
                            eventid4688 = True
                            break
                if not eventid4688:
                    break
            if 'EventData' in y.tag:
                for z in y:
                    if z.attrib['Name'] == 'NewProcessName' and ('net.exe' in z.text or 'net1.exe' in z.text):
                        alert = True
                        break
    if alert:
        action_alert = "local"
        description = "Account discovery"
    else:
        action_alert = None
        description = None
    return action_alert, description


# https://attack.mitre.org/techniques/T1134/
def rule2_priviledge_escalation(filename):
    ret = parse_evtx_to_xml(filename)
    dump_xmlstr_to_file(ret, r'test/resources/rule2.xml')
    xmltree = ET.parse(r'test/resources/rule2.xml')
    xmlroot = xmltree.getroot()

    alert = False
    eventid4688 = False
    for x in range(len(xmlroot)):
        for y in xmlroot[x]:
            if 'System' in y.tag:
                for z in y:
                    if 'EventID' in z.tag:
                        if z.text == '4688':
                            eventid4688 = True
                            break
                if not eventid4688:
                    break
            if 'EventData' in y.tag:
                for z in y:
                    if z.attrib['Name'] == 'NewProcessName' and 'runas.exe' in z.text:
                        alert = True
                        break
    if alert:
        action_alert = "remote"
        description = "Possible priviledge escalation"
    else:
        action_alert = None
        description = None

    return action_alert, description


# https://attack.mitre.org/techniques/T1110/
def rule3_brute_force(filename):
    ret = parse_evtx_to_xml(filename)
    dump_xmlstr_to_file(ret, r'test/resources/rule3.xml')
    xmltree = ET.parse(r'test/resources/rule3.xml')
    xmlroot = xmltree.getroot()

    failed_logons = 0

    alert = False
    for x in range(len(xmlroot)):
        for y in xmlroot[x]:
            if 'System' in y.tag:
                for z in y:
                    if 'EventID' in z.tag:
                        if z.text == '4625':
                            failed_logons += 1
                            if failed_logons >= 5:
                                alert = True
    if alert:
        action_alert = "remote"
        description = "Possible brute force attack"
    else:
        action_alert = None
        description = None

    return action_alert, description


# https://attack.mitre.org/techniques/T1040/
def rule4_credential_access(filename):
    ret = parse_evtx_to_xml(filename)
    dump_xmlstr_to_file(ret, r'test/resources/rule4.xml')
    xmltree = ET.parse(r'test/resources/rule4.xml')
    xmlroot = xmltree.getroot()

    alert = False
    eventid4688 = False
    for x in range(len(xmlroot)):
        for y in xmlroot[x]:
            if 'System' in y.tag:
                for z in y:
                    if 'EventID' in z.tag:
                        if z.text == '4688':
                            eventid4688 = True
                            break
                if not eventid4688:
                    break
            if 'EventData' in y.tag:
                for z in y:
                    if z.attrib['Name'] == 'NewProcessName' and 'PktMon.exe' in z.text:
                        alert = True
                        break
    if alert:
        action_alert = "local"
        description = "Packet monitor (PktMon.exe) turned on."
    else:
        action_alert = None
        description = None

    return action_alert, description


# https://attack.mitre.org/techniques/T1070/001/
def rule5_event_log_cleared(filename):
    ret = parse_evtx_to_xml(filename)
    dump_xmlstr_to_file(ret, r'test/resources/rule5.xml')
    xmltree = ET.parse(r'test/resources/rule5.xml')
    xmlroot = xmltree.getroot()

    alert = False
    for x in range(len(xmlroot)):
        for y in xmlroot[x]:
            if 'System' in y.tag:
                for z in y:
                    if 'EventID' in z.tag:
                        if z.text == '104' or z.text == '1102':
                            alert = True
    if alert:
        action_alert = "local"
        description = "Windows Event Log cleared."
    else:
        action_alert = None
        description = None

    return action_alert, description


# https://attack.mitre.org/techniques/T1562/002/
def rule6_disable_event_logging(filename):
    ret = parse_evtx_to_xml(filename)
    dump_xmlstr_to_file(ret, r'test/resources/rule6.xml')
    xmltree = ET.parse(r'test/resources/rule6.xml')
    xmlroot = xmltree.getroot()

    alert = False

    for x in range(len(xmlroot)):
        for y in xmlroot[x]:
            if 'System' in y.tag:
                for z in y:
                    if 'EventID' in z.tag:
                        if z.text == '4719':
                            alert = True
    if alert:
        action_alert = "local"
        description = "System audit policy changed."
    else:
        action_alert = None
        description = None

    return action_alert, description


# https://attack.mitre.org/techniques/T1078/002/
def rule7_special_member_login(filename):
    ret = parse_evtx_to_xml(filename) 
    dump_xmlstr_to_file(ret, r'test/resources/rule7.xml')
    xmltree = ET.parse(r'test/resources/rule7.xml')
    xmlroot = xmltree.getroot()

    alert = False

    for x in range(len(xmlroot)):
        for y in xmlroot[x]:
            if 'System' in y.tag:
                for z in y:
                    if 'EventID' in z.tag:
                        if z.text == '4964':
                            alert = True
    if alert:
        action_alert = "local"
        description = "Member of a special group succesfully logged in."
    else:
        action_alert = None
        description = None

    return action_alert, description


# https://attack.mitre.org/techniques/T1087/001/
def rule8_json_account_discovery(filename): 
    filepath = filename
    alert = False
    if search(filepath, 'net user') or search(filepath, 'net account') or search(filepath, 'net localgroup')\
            or search(filepath, 'Get-LocalUser') or search(filepath, 'dscl'):
        alert = True
    if alert:
        action_alert = "local"
        description = "Account discovery (local users enumeration)."
    else:
        action_alert = None
        description = None

    return action_alert, description

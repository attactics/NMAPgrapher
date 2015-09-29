import xml.etree.ElementTree as ET
import operator
import csv
import os
import lxml
import shutil
import sys
import pygal
import argparse

allhosts = []

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
class HostObj(object):
    def __init__(self,ipAddr,tcpPorts,udpPorts,services,detailedServices,operSys):
        self.ipAddr=ipAddr
        self.tcpPorts=tcpPorts
        self.udpPorts=udpPorts
        self.services=services
        self.detailedServices=detailedServices
        self.operSys=operSys

def populateObjects(file):
	e = ET.parse(file).getroot()
	tcpPortList = []
	udpPortList = []
	detailedServiceList = []
	serviceList = []
	osList = []
	for child in e:
		for port in child:
			if port.tag == "address":
				ipAddr = port.attrib['addr']
			topOS = False
			for lol in port:
				if lol.tag =="osmatch":
					if lol.attrib['name']:
						if not topOS:
							osList.append(lol.attrib['name'])
							topOS = True
				if lol.tag == "port":
					if lol.attrib['protocol'] == 'tcp':
						tcpPortList.append(lol.attrib['portid'])
					if lol.attrib['protocol'] == 'udp':
						udpPortList.append(lol.attrib['portid'])
					for service in lol:
						if service.tag == "service":
							detailedServiceList.append(lol.attrib['protocol']+'/'+lol.attrib['portid']+' '+ service.attrib['name'])
							serviceList.append(service.attrib['name'])
							
			if tcpPortList or udpPortList:
				allhosts.append(HostObj(ipAddr, tcpPortList, udpPortList, serviceList, detailedServiceList, osList))
				tcpPortList = []
				udpPortList = []
				serviceList = []
				detailedServiceList = []
				osList = []

def generateHostPortListOutput(list,filename):
	shutil.copy('css/styles.css', args.outputBaseName+'/styles.css')
	f=open(args.outputBaseName+'/'+filename+'.html','w+')
	f.write('<!DOCTYPE html>\n<html>\n<head>\n<link rel="stylesheet" href="styles.css">\n</head>\n<body>\n')
	for item in list:
		f.write('<div class="table">\n<table class="table">\n<tr>\n')
		f.write('<td>\n'+item[0]+'\n</td>\n')
		f.write('</tr>\n')
		if item[1]:
		 	for tcpPort in item[1]:
				f.write('<tr>\n')
				f.write('<td> TCP '+str(tcpPort)+'</td>')
				f.write('</tr>\n')
		f.write('</table>\n</div>\n<br>\n<br>')
	f.write('\n</body>\n</html>')
	f.close

def generateOutput(list, title, headers, filename, outputFormat):
	if not os.path.exists(args.outputBaseName):
		os.makedirs(args.outputBaseName)
	if outputFormat == 'html':
		shutil.copy('css/styles.css', args.outputBaseName+'/styles.css')
		f=open(args.outputBaseName+'/'+filename+'.html','w+')
		f.write('<!DOCTYPE html>\n<html>\n<head>\n<link rel="stylesheet" href="styles.css">\n</head>\n<body>\n')
		f.write('<h1 class="title">\n'+title+'</h1>\n')
		f.write('<div class="table">\n<table class="table">\n<tr>\n')
		for i in range(len(headers)):
			f.write('<td>\n'+headers[i]+'\n</td>\n')
		f.write('</tr>\n')
		for item in list:
			f.write('<tr>\n')
			for i in range(len(headers)):
				f.write('<td>'+str(item[i])+'</td>')
			f.write('</tr>\n')
		f.write('</table>\n</body>\n</html>')
		f.close
	elif outputFormat == 'csv':
		f=open(args.outputBaseName+'/'+filename,'w+')
		wrcsv = csv.writer(f, delimiter=',')
		wrcsv.writerow(headers)
		for item in list:
			wrcsv.writerow(item)
		f.close
	else:
		x = []
		y = []
		bar_chart=pygal.Bar(x_label_rotation=50, human_redable=True)
		for row in list:
			x.append(row[0])
			y.append(row[1])
		bar_chart.title = title
		bar_chart.x_labels = map(str, x)
		bar_chart.add('Total', y)
		if outputFormat == "png":
			bar_chart.render_to_png(args.outputBaseName+'/'+filename+'.png')
		if outputFormat == "svg":
			bar_chart.render_to_file(args.outputBaseName+'/'+filename+'.svg')

def printBanner():
    banner=""" _   _ __  __    _    ____                       _
| \ | |  \/  |  / \  |  _ \ __ _ _ __ __ _ _ __ | |__   ___ _ __
|  \| | |\/| | / _ \ | |_) / _` | \'__/ _` | \'_ \| \'_ \ / _ \ \'__|
| |\  | |  | |/ ___ \|  __/ (_| | | | (_| | |_) | | | |  __/ |
|_| \_|_|  |_/_/   \_\_|   \__, |_|  \__,_| .__/|_| |_|\___|_|
              attactics.org|___/          |_|@evasiv3
   | Generates graph, html, and csv data from NMAP XML files |      """
    print banner
    print ''

def getPorts(number, sort, typePort):
    allPorts = []
    for host in allhosts:
        if typePort == "tcp":
            for port in host.tcpPorts:
                allPorts.append(port)
        if typePort == "udp":
            for port in host.udpPorts:
                allPorts.append(port)
        if typePort == "both":
            for port in host.tcpPorts:
                allPorts.append(port)
            for port in host.udpPorts:
                allPorts.append(port)
    # Get only unique values
    allPortsSet = set(allPorts)
    totals = []
    for port in allPortsSet:
        list = []
        list.append(port)
        list.append(allPorts.count(port))
        totals.append(list)
    if sort == "top":
        return sorted(totals, key=operator.itemgetter(1),reverse=True)[:number]
    else:
        return sorted(totals, key=operator.itemgetter(1))[:number]

def checkArgs(args):
	if not os.path.isfile(args.inputFile):
		print bcolors.FAIL + ' [!] - Input file cannot be found. Quitting...' + bcolors.ENDC
		sys.exit()
	if args.tports and args.tports not in ['tcp', 'udp', 'both']:
		print bcolors.FAIL + ' [!] - Invalid port type specified. Quitting...' + bcolors.ENDC
		sys.exit()
	if args.outputFormat not in ['csv','svg','png','html']:
		print bcolors.FAIL + ' [!] - Invalid output type specified. Quitting...' + bcolors.ENDC 
		sys.exit()
	if not args.c:
		print bcolors.WARNING + '[!] - Custom item count not specified, defaulting to 10.' + bcolors.ENDC

def getOperSys(number, sort):
    allOperSys = []
    for host in allhosts:
        for operSys in host.operSys:
            allOperSys.append(operSys)
    # Get only unique values
    allOperSysSet = set(allOperSys)
    totals = []
    for operSys in allOperSysSet:
        list = []
        list.append(operSys)
        list.append(allOperSys.count(operSys))
        totals.append(list)
    if sort == "top":
        return sorted(totals, key=operator.itemgetter(1),reverse=True)[:number]
    else:
        return sorted(totals, key=operator.itemgetter(1))[:number]

def getServices(number, sort):
    allServices = []
    for host in allhosts:
        for port in host.services:
            allServices.append(port)
    # Get only unique values
    allServicesSet = set(allServices)
    totals = []
    for service in allServicesSet:
        list = []
        list.append(service)
        list.append(allServices.count(service))
        totals.append(list)
    if sort == "top":
        return sorted(totals, key=operator.itemgetter(1),reverse=True)[:number]
    else:
        return sorted(totals, key=operator.itemgetter(1))[:number]

def getHosts(number,sort):
    totals = []
    for host in allhosts:
        list = []
        list.append(host.ipAddr)
        list.append(len(host.tcpPorts)+len(host.udpPorts))
        totals.append(list)
    if sort == "top":
        return sorted(totals, key=operator.itemgetter(1),reverse=True)[:number]
    else:
        return sorted(totals, key=operator.itemgetter(1))[:number]

def getHostPortList():
	list = []
	for host in allhosts:
		list.append([host.ipAddr, host.detailedServices])
	return list
		


parser = argparse.ArgumentParser(description='\n      * If optional graph flags are not specified: *\n\t  - All graphs are outputted\n\t  - Port counts will include TCP and UDP\n\t  - Item count will default to 10',formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('inputFile', help='Input file. Options:\n    NMAP XML')
parser.add_argument('outputBaseName', help='Output file(s) base name\n')
parser.add_argument('outputFormat', help='Output format: \n    svg\n    png\n    csv\n    html')
parser.add_argument('-c', help='Number of items to include in graphs.')
parser.add_argument('-tports', metavar="TYPE", help='Most common ports. Types are:\n    tcp\n    udp\n    both')
parser.add_argument('-bports', metavar="TYPE", help='Least common ports. Types are:\n    tcp\n    udp\n    both')
parser.add_argument('-tservices', help='Most common services.', action="store_true")
parser.add_argument('-bservices', help='Least common services.', action="store_true")
parser.add_argument('-tos', help='Most common operating systems.', action="store_true")
parser.add_argument('-bos', help='Least common operating systems.', action="store_true")
parser.add_argument('-thosts', help='Hosts with most open ports', action="store_true")
parser.add_argument('-bhosts', help='Hosts with least open ports', action="store_true")
args = parser.parse_args()
printBanner()
checkArgs(args)
populateObjects(args.inputFile)

if args.c == None:
    args.c = '10'
if (args.tports == None) and (args.bports == None) and (args.tservices == False) and (args.bservices == False) and (args.tos == False) and (args.bos == False) and (args.thosts == False) and (args.bhosts == False):
    print bcolors.WARNING + '[+] - No output flags specified, generating default outputs in '+args.outputFormat+' format.' + bcolors.ENDC
    args.tports = 'both'
    args.bports = 'both'
    args.tservices = True
    args.bservices = True
    args.tos = True
    args.hostList = True
    args.bos = True
    args.thosts = True
    args.bhosts = True
checkArgs(args)
if args.tports:
    res = getPorts(int(args.c),'top',args.tports)
    if not res:
        print bcolors.WARNING + '[!] - No port info found, related output will not be generated.' + bcolors.ENDC
    else:
        generateOutput(res, 'Top '+args.c+' Most Common Ports', ['Port','Total'], args.outputBaseName+'_Top'+args.c+'Ports', args.outputFormat)
        print bcolors.OKGREEN + '[+] - Generated \'Top '+args.c+' Most Common Ports\' output in '+args.outputFormat+' format.' + bcolors.ENDC
if args.hostList:
	if args.outputFormat != 'html':
		print bcolors.WARNING + '[!] - \'All Hosts\' Services\' output is only generated in HTML.' + bcolors.ENDC
	res = getHostPortList()
	if not res:
		print bcolors.WARNING + '[!] - No detailed host service info found, related output will not be generated.' + bcolors.ENDC
	else:
		generateHostPortListOutput(res, args.outputBaseName+'_hostList.html')
        print bcolors.OKGREEN + '[+] - Generated \'All Hosts\' Services\' output in html format.' + bcolors.ENDC
if args.bports:
    res = getPorts(int(args.c),'bottom',args.tports)
    if not res:
        print bcolors.WARNING + '[!] - No port info found, related output will not be generated.' + bcolors.ENDC
    else:
        generateOutput(res, 'Top '+args.c+' Least Common Ports', ['Port','Total'], args.outputBaseName+'_Bottom'+args.c+'Ports', args.outputFormat)
        print bcolors.OKGREEN + '[+] - Generated \'Top '+args.c+' Least Common Ports\' output in '+args.outputFormat+' format.' + bcolors.ENDC
if args.tservices:
    res = getServices(int(args.c),'top')
    if not res:
        print bcolors.WARNING + '[!] - No service info found, related output will not be generated.' + bcolors.ENDC
    else:
        generateOutput(res, 'Top '+args.c+' Most Common Services', ['Service','Total'], args.outputBaseName+'_Top'+args.c+'Services', args.outputFormat)
        print bcolors.OKGREEN + '[+] - Generated \'Top '+args.c+' Most Common Services\' output in '+args.outputFormat+' format.' + bcolors.ENDC
if args.bservices:
    res = getServices(int(args.c),'bottom')
    if not res:
        print bcolors.WARNING + '[!] - No service info found, related output will not be generated.' + bcolors.ENDC
    else:
        generateOutput(res, 'Top '+args.c+' Least Common Services', ['Service','Total'], args.outputBaseName+'_Bottom'+args.c+'Services', args.outputFormat)
        print bcolors.OKGREEN + '[+] - Generated \'Top '+args.c+' Least Common Services\' output in '+args.outputFormat+' format.' + bcolors.ENDC
if args.tos:
    res = getOperSys(int(args.c),'top')
    if not res:
        print bcolors.WARNING + '[!] - No operating system info found, related output will not be generated.' + bcolors.ENDC
    else:
        generateOutput(res, 'Top '+args.c+' Most Common Operating Systems', ['Operating System', 'Total'], args.outputBaseName+'_Top'+args.c+'OperatingSystems', args.outputFormat)
        print bcolors.OKGREEN + '[+] - Generated \'Top '+args.c+' Most Common Operating Systems\' output in '+args.outputFormat+' format.' + bcolors.ENDC
if args.bos:
    res = getOperSys(int(args.c),'bottom')
    if not res:
        print bcolors.WARNING + '[!] - No operating system info found, related output will not be generated.' + bcolors.ENDC
    else:
        generateOutput(res, args.c+' Least Common Operating Systems', ['Operating System', 'Total'], args.outputBaseName+'_Bottom'+args.c+'OperatingSystems', args.outputFormat)
        print bcolors.OKGREEN + '[+] - Generated \'Top '+args.c+' Least Common Operating Systems\' output in '+args.outputFormat+' format.' + bcolors.ENDC
if args.thosts:
    res = getHosts(int(args.c),'top')
    if not res:
        print bcolors.WARNING + '[!] - No host info found, related output will not be generated.' + bcolors.ENDC
    else:
        generateOutput(res, 'Top '+args.c+' Hosts with Most Open Ports', ['Host', 'Total'], args.outputBaseName+'_Top'+args.c+'Hosts', args.outputFormat)
        print bcolors.OKGREEN + '[+] - Generated \'Top '+args.c+' Hosts with Most Open Ports\' output in '+args.outputFormat+' format.' + bcolors.ENDC
if args.bhosts:
    res = getHosts(int(args.c),'bottom')
    if not res:
        print bcolors.WARNING + '[!] - No host info found, related output will not be generated.' + bcolors.ENDC
    else:
        generateOutput(res, 'Top '+args.c+' Hosts with Least Open Ports', ['Host', 'Total'], args.outputBaseName+'_Bottom'+args.c+'Hosts', args.outputFormat)
        print bcolors.OKGREEN + '[+] - Generated \'Top '+args.c+' Hosts with Least Open Ports\' output in '+args.outputFormat+' format.' + bcolors.ENDC
print bcolors.OKGREEN + '[+] - Done.' + bcolors.ENDC

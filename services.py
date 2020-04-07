#!/usr/bin/python3

import xml.etree.ElementTree as ET
import urllib.request
import ssl,os,sys
import argparse
from datetime import datetime
import time

class PALO_ALTO(object):
	def __init__(self):
		self.lendo_args_cli()

		if self.args.list:
			self.resposta = self.listar(self.args.firewall)

		elif self.args.commit:
			self.resposta = self.commit(self.args.firewall)

		elif self.args.globalprotect:
			self.resposta = self.globalprotect(self.args.firewall)
			lista=self.resposta[0]
			useronline=self.resposta[1]
			userpossiveis=self.resposta[2]
			print('Lista de usuários:')
			for i in lista:
				print(i)
			print('')
			print('Existem '+useronline+' de usuários on-line atualmente')
			print('Existem '+userpossiveis+' de usuários posiveis')

		elif self.args.job:
			self.resposta = self.get_job(self.args.firewall,self.args.job)		 			

		elif self.args.set:
			if self.args.firewall or self.args.objeto is None:
				self.resposta = self.set(self.args.firewall,self.args.objeto)
			else:
				self.resposta = self.help(self.args.firewall,self.args.objeto)
	
		if self.args.globalprotect is False:
			print(self.resposta)

	def help(self,FW,OBJETO):
		checkexiste=self.listar(FW)
		if OBJETO not in checkexiste:
			return 'Esse objeto '+OBJETO+' não existe.\nUse -f [Endereço IP do Firewall] -o [Nome do Agendamento]'
		else:
			return 'Use -f [Endereço IP do Firewall] -o [Nome do Agendamento]'

	def set_schedule(self,LINK):
		context = ssl._create_unverified_context()
		try:
			if DebugLevel == 1:
				print(LINK)
			pagina=urllib.request.urlopen(LINK,context=context)
		except:
			print ("error 1")
			exit(1)
		dom=ET.parse(pagina)
		xml=dom.findall('msg')
		for i in xml:
			name=i.text
		return name

	def listar(self,FW):
		lista=[]
		context = ssl._create_unverified_context()
		key = '&key='+PrivateKey
		xpath ='&xpath=/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/schedule'
		url = 'https://'+FW+'/api/?type=config&action=get'+xpath+key
		if DebugLevel == 1:
			print(url)
		pagina=urllib.request.urlopen(url,context=context)
		dom=ET.parse(pagina)
		root = dom.getroot()
		for elem in root.iter():
			try:
				e=elem.attrib['name']
				lista.append(e)
			except:
				error='Error'
		return lista

	def commit(self,FW):
		context = ssl._create_unverified_context()
		key = '&key='+PrivateKey
		url = 'https://'+FW+'/api/?type=commit&cmd=<commit></commit>'+key
		if DebugLevel == 1:
			print(url)		
		print('Tentando aplicar alterações no firewall ...')
		pagina=urllib.request.urlopen(url,context=context)
		dom=ET.parse(pagina)
		xml=dom.findall('msg')
		
		for i in xml:
			name=i.text

		if 'name' in locals():
			return name
		else:
			xml=dom.findall('result/job')
			for i in xml:
				jobid=i.text
				time.sleep(80)
				resultado = self.get_job(FW,jobid)
				return resultado

	def get_job(self,FW,JOBID):
		context = ssl._create_unverified_context()
		key = '&key='+PrivateKey
		url = 'https://'+FW+'/api/?type=op&cmd=<show><jobs><id>'+JOBID+'</id></jobs></show>'+key
		if DebugLevel == 1:
			print(url)
		pagina=urllib.request.urlopen(url,context=context)
		dom=ET.parse(pagina)
		xml=dom.findall('result/job/details/line')
		for i in xml:
			if 'successfully' in i.text:
				return i.text

	def set(self,FW,OBJETO):
		checkexiste=self.listar(FW)
		if OBJETO in checkexiste:
			HORARIO=self.get_hora()
			key = '&key='+PrivateKey
			xpath='&xpath=/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/schedule/entry[@name=\''+OBJETO+'\']&element=<schedule-type><non-recurring><member>'+HORARIO+'</member></non-recurring></schedule-type>'
			url='https://'+FW+'/api/?type=config&action=set'+xpath+key
			if DebugLevel == 1:
				print(url)
			return self.set_schedule(url)
		else:
			return self.help(FW,OBJETO)

	def get_hora(self):
		diaria = datetime.now().strftime('%Y/%m/%d')
		diaria = diaria+'@08:00-'+diaria+'@23:59'
		return diaria

	def globalprotect(self,FW):
		context = ssl._create_unverified_context()
		key = '&key='+PrivateKey
		xpath ='<show><global-protect-gateway><current-user/></global-protect-gateway></show>'
		url = 'https://'+FW+'/api/?type=op&cmd='+xpath+key
		if DebugLevel == 1:
			print(url)
		pagina=urllib.request.urlopen(url,context=context)
		dom=ET.parse(pagina)
		xml=dom.findall('result/entry')
		lista=[]
		for i in xml:
			username=i.find('username').text
			lista.append(username)
		
		context = ssl._create_unverified_context()
		key = '&key='+PrivateKey
		xpath ='<show><global-protect-gateway><statistics><gateway>GW%20Base%20Local</gateway></statistics></global-protect-gateway></show>'
		url = 'https://'+FW+'/api/?type=op&cmd='+xpath+key
		if DebugLevel == 1:
			print(url)
		pagina=urllib.request.urlopen(url,context=context)
		dom=ET.parse(pagina)
		xml=dom.findall('result/Gateway')
		for i in xml:
			users_total=i.find('CurrentUsers').text
			users_previsto=i.find('PreviousUsers').text
		
		return lista,users_total,users_previsto

	def lendo_args_cli(self):
		parser = argparse.ArgumentParser()
		group = parser.add_mutually_exclusive_group()		
		group.add_argument('-l', '--list', help="listar schedules do firewall Palo Alto",action="store_true")
		group.add_argument('-c', '--commit', help="Aplicar configurações do Firewall",action="store_true")
		group.add_argument('-s', '--set', help="Setar schedule  do firewall Palo Alto com a data do dia anterior até às 29:59 do mesmo dia",action="store_true")
		group.add_argument('-g', '--globalprotect',help="Verificar quantos usuários existem conectados no GP",action="store_true")		
		parser.add_argument('-o', '--objeto', type=str, help="Shedule ja configurada no firewall")
		parser.add_argument('-f', '--firewall', type=str, help="Endereço IP do firewall Palo Alto")
		parser.add_argument('-j', '--job', type=str, help="Verificar Jobs dos commits do PaloAlto")		

		self.args = parser.parse_args()
    
if __name__ == '__main__':
    
    DebugLevel=0
    global PrivateKey
    PrivateKey = 'sdjfklfjmbnaskklasdjga'    
    PALO_ALTO()


import os #module provides easy functions that allow us to interact and get Operating System information and even control processes up to a limit
import ssl# provides access to Transport Layer Security (often known as “Secure Sockets Layer”) encryption and peer authentication facilities for network sockets, both client-side and server-side. This module uses the OpenSSL library. 
#SSL stands for Secure Sockets Layer and is designed to create secure connection between client and server. Secure means that connection is encrypted and therefore protected from eavesdropping. It also allows to validate server identity.
import socket# one of the endpoints in a communication between programs on some network.
#A socket will be tied to some port on some host. In general, you will have either a client or a server type of entity or program.

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

def cert(hostname, sslp, output, data):#hostname="google.com" #sslp= port number=443
	result = {}#stored in dictionary
	pair = {}
	print ('\n' + Y + '[!]' + Y + ' SSL Certificate Information : ' + W + '\n')
	# create an INET, STREAMing socket
	pt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	pt.settimeout(5)#Any code that's using a socket with a timeout and isn't ready to handle socket.timeout exception will likely fail. It is more reliable to remember the socket's timeout value before you start your operation, and restore it when you are done:
	try:
		pt.connect((hostname, sslp))#connect() initiates a connection on a socket.
		pt.close()#shuts down

		ctx = ssl.create_default_context()#The helper functions create_default_context() returns a new context with secure default settings.

		#For client use, if you don’t have any special requirements for your security policy, it is highly recommended that you use the create_default_context() function to create your SSL context. It will load the system’s trusted CA certificates, enable certificate validation and hostname checking, and try to choose reasonably secure protocol and cipher settings. 
		sock = socket.socket() #provides a socket-like wrapper that also encrypts and decrypts the data going over the socket with SSL.
		sock.settimeout(5)
		s = ctx.wrap_socket(sock, server_hostname=hostname) #to wrap sockets as SSLSocket objects

		try:
			s.connect((hostname, sslp))
			info = s.getpeercert()#which retrieves the certificate of the other side of the connection
		except:
			info = ssl.get_server_certificate((hostname, sslp)) #fetches the server’s certificate, and returns it as a PEM-encoded string.
			f = open('{}.pem'.format(hostname), 'w')
			f.write(info)
			f.close()
			cert_dict = ssl._ssl._test_decode_cert('{}.pem'.format(hostname))
			info = cert_dict
			os.remove('{}.pem'.format(hostname))#used to remove or delete a file path. This method can not remove or delete a directory

		def unpack(v, pair):
			convert = False
			for item in v:
				if isinstance(item, tuple):
					for subitem in item:
						if isinstance(subitem, tuple):
							for elem in subitem:
								if isinstance(elem, tuple):
									unpack(elem)
								else:
									convert = True
									pass
							if convert == True:
								pair.update(dict([subitem]))
						else:
							pass
				else:
					print(G + '[+]' + C + ' {} : '.format(str(k)) + W + str(item))
					if output != 'None':
						result.update({k:v})

		for k, v in info.items():
			if isinstance(v, tuple):
				unpack(v, pair)
				for k,v in pair.items():
					print(G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v))
					if output != 'None':
						result.update({k:v})
				pair.clear()
			else:
				print(G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v))
			if output != 'None':
				result.update({k:v})

	except:
		pt.close()
		print (R + '[-]' + C + ' SSL is not Present on Target URL...Skipping...' + W)
		if output != 'None':
			result.update({'Error':'SSL is not Present on Target URL'})

	if output != 'None':
		cert_output(output, data, result)

#def cert_output(output, data, result):
#	data['module-SSL Certificate Information'] = result
def outputToFile():
	try:
		print("exporting the results to"+'sslinfo.txt')
		path="./results/sslinfo.txt"
		filehandler=open(path,'a')
		filehandler.write("-----------INFO------------"+'\n')
		filehandler.write(str(port(result))
		filehandler.close()
	except:
		print("unable to write to file")

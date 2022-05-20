import sys
import re
#import validators
import ipaddress


def domain_checker(value):
	#if not validators.domain(value):

	if not value:
		print("FAIL: missing domain name value")
		return

	try:
		ipaddress.ip_address(value)
		print("FAIL: The value is not a domain name:", value)
		return
	except:
		pass

	if "%" in value:
		# TODO: later check for macro
		return
	elif "." not in value:
		print("FAIL: This is not a valid domain name:", value)


def ip_address_checker(value, ip_type):

	if not value:
		print("FAIL: missing IP address")
		return

	try:
		ipaddress.ip_address(value)
		if ipaddress.ip_address(value).version != ip_type:
			print("FAIL: The value is not an IPv" + str(ip_type) + " address:", value)
	except:
		print("FAIL: The value is not an IP address:", value)

def ip_cidr_checker(value, ip_type):
	index = value.index("/")
	try:
		value = int(value[index+1:])
	except:
		print("FAIL: CIDR should be a number:", value)
		return
	if ip_type == 4:
		if value < 0 or value > 32:
			print("FAIL: IPv4 CIDR value range should be 0 to 32:", value)
	else:
		if value < 0 or value > 128:
			print("FAIL: IPv6 CIDR value range should be 0 to 128:", value)
	#print("debug", value)


prev_owner = ""

for line in sys.stdin.readlines():
	
	if line == "\n":
		continue
	
	# no space or tab in first qname
	rrset = re.search(r'^([^ 	]+).*\s(TXT)\s+(.*)$', line)

	rdata = rrset.group(3)

	if not rdata:
		continue

	rdata = rdata.replace('" "', '')
	rdata = rdata.replace('"', '')

	if rdata[:7] == "v=spf1 ":

		print(line, end="")

		owner = rrset.group(1)
		if owner == prev_owner:
			print("FAIL: SPF record must be a single record:", owner)
		prev_owner = owner

		mechanism_list = rdata[6:].strip().split(" ")
		#print(mechanism_list)
		for item in mechanism_list:

			if not item:
				continue

			if ':' in item:
				(key,value) = item.split(":", 1)
			else:
				key = item
				value = None

			# chopped modifier
			if key[0:1] in "+?~-":
				key = key[1:]

			key = key.lower()

			if key == "all":
				if value is not None:
					print("FAIL: All mechanism should not have a value:", value)

			elif key == "include":
				domain_checker(value)

			elif key == "a" or key[:2] == "a/":
				if value:
					if "/" in value:
						value2 = value.split("/")
						domain_checker(value2[0])
						ip_cidr_checker(value, None)
					else:
						domain_checker(value)
				elif key[:2] == "a/":
					ip_cidr_checker(key, None)

			elif key == "mx" or key[:3] == "mx/":
				if value:
					if "/" in value:
						value2 = value.split("/")
						domain_checker(value2[0])
						ip_cidr_checker(value, None)
					else:
						domain_checker(value)
				elif key[:3] == "mx/":
					ip_cidr_checker(key, None)

			elif key == "ptr":
				print("WARNING: it is recommended to not use ptr mechanism")
				if value:
					domain_checker(value)

			elif key == "ip4":
				if "/" in value:
					value2 = value.split("/")
					ip_address_checker(value2[0], 4)
					ip_cidr_checker(value, 4)
				else:
					ip_address_checker(value, 4)

			elif key == "ip6":
				if "/" in value:
					value2 = value.split("/")
					ip_address_checker(value2[0], 6)
					ip_cidr_checker(value, 6)
				else:
					ip_address_checker(value, 6)

			elif key == "exists":
				domain_checker(value)

			elif "=" in key:
				key2, value2 = key.split("=", 1)
				if key2 == "redirect" or key2 == "exp":
					domain_checker(value2)
				else:
					print("FAIL: Unknown modifier:", item)

			else:
				print("FAIL: Unknown mechanism:", item)
	print()


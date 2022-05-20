import sys
#import validators

for line in sys.stdin.readlines():
	print(line)
	
	line = line.replace('" "', '')
	line = line.replace('"', '')
	
	if line[:6] != "v=spf1":
		print("Error, the string does not begin with 'v=spf1'")
	else:
		mechanism_list = line.strip().split(" ")
		#print(mechanism_list)
		for item in mechanism_list:
			(key,value) = item.split(":")
			if key[0:1] in "+?~-":
				key = key[1:]
			if key == "a":
				pass
			#if validators.domain(key):
			#	print("worked")
				
				

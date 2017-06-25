def pad(data):
	data += '=' * (len(data) % 4)
	return data

def depad(data):
	return data.rstrip('=')

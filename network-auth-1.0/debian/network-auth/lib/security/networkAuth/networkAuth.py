import subprocess

def authenticate(pamh):
	"""Return PAM exit value that corresponds to whether or not
		network is recognized"""
	# Get the MAC address of the router
	# and encrypt it using a series of SHA sums
	mac = subprocess.Popen("arp -a | grep $(route | grep 'default' | awk '{ print $2 }') | awk '{ print $4 }' | sha512sum | sha224sum | sha384sum | sha1sum | sha256sum", shell=True, stdout=subprocess.PIPE).communicate()[0]
	mac = mac[:64] + "\n"
	# Get a list of allowed mac addresses
	routerMACs = open("/etc/networkAuth/routerMACs")
	allowedMACs = routerMACs.readlines()
	routerMACs.close()
	# Find out if this router is allowed
	if mac in allowedMACs:
		return pamh.PAM_SUCCESS
	else:
		return pamh.PAM_AUTH_ERROR

# If user tries to authenticate or login, run authenticate()
def pam_sm_authenticate(pamh, flags, args):
	return authenticate(pamh)

def pam_sm_open_session(pamh, flags, args):
	return authenticate(pamh)

# In all other cases, ignore this module
def pam_sm_acct_mgmt(pamh, flags, args):
	return pamh.PAM_IGNORE

def pam_sm_close_session(pamh, flags, args):
	return pamh.PAM_IGNORE

def pam_sm_chauthtok(pamh, flags, args):
	return pamh.PAM_IGNORE

def pam_sm_setcred(pamh, flags, args):
	return pamh.PAM_IGNORE

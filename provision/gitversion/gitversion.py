from subprocess import Popen, PIPE
import os
import os.path as path

def call_git_rev_parse():
	try:
		p = Popen(['git', 'rev-parse', 'HEAD'], stdout=PIPE, stderr=PIPE)
		p.stderr.close()
		line = "Git commit ID: " + p.stdout.readlines()[0].decode()
		p = Popen(['date', '-u', '+%m-%d-%Y.%H:%M:%S.UTC'], stdout=PIPE, stderr=PIPE)
		p.stderr.close()
		line = line + "Build time: " + p.stdout.readlines()[0].decode()
		return (line.strip(), line.replace('\n', ' '))

	except:
		return (None, None)


def read_release_version():
	try:
		script_dir = path.abspath(path.join(__file__ ,"../.."))
		with open(script_dir + "/acc_provision/RELEASE-VERSION", "r") as f:
			version = f.readlines()[0]
			f.close()
			return version.strip()

	except:
		return None


def write_release_version(version):
	script_dir = path.abspath(path.join(__file__ ,"../.."))
	with open(script_dir + "/acc_provision/RELEASE-VERSION", "w") as f:
		f.write("%s\n" % version)
		f.close()


def get_git_version():
	# Read in the version that's currently in RELEASE-VERSION.
	release_version = read_release_version()

	version, version_formatted = call_git_rev_parse()

	# If that doesn't work, fall back on the value that's in
	# RELEASE-VERSION.

	if version is None:
		version = release_version

	if version is None:
		write_release_version("Release info not in the current build.")
	# If the current version is different from what's in the
	# RELEASE-VERSION file, update the file to be current.
	elif version != release_version:
		write_release_version(version)

	if version_formatted is None:
        	version_formatted = "Release info not in the current build."
	
	return version_formatted

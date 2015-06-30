#!python -u

import os, sys
import datetime
import re
import glob
import subprocess
import shutil
import time

def next_build_number():
    try:
        file = open('.build_number', 'r')
        build_number = file.read()
        file.close()
    except IOError:
        build_number = '0'

    file = open('.build_number', 'w')
    file.write(str(int(build_number) + 1))
    file.close()

    return build_number


def get_configuration(release, debug):
    configuration = release

    if debug:
        configuration += ' Debug'
    else:
        configuration += ' Release'

    return configuration


def get_target_path(release, arch, debug, vs):
    configuration = get_configuration(release, debug)
    name = ''.join(configuration.split(' '))
    target = { 'x86': os.sep.join([name, 'Win32']), 'x64': os.sep.join([name, 'x64']) }
    target_path = os.sep.join([vs, target[arch]])

    return target_path


def shell(command, dir):
    print(dir)
    print(command)
    sys.stdout.flush()
    
    sub = subprocess.Popen(' '.join(command), cwd=dir,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)

    for line in sub.stdout:
        print(line.decode(sys.getdefaultencoding()).rstrip())

    sub.wait()

    return sub.returncode


def update_cert_path(name, vs, path):
    for pkg in os.listdir(vs):
        if not os.path.isdir(os.path.join(vs, pkg)):
            continue
        vxproj_path = "{vs}/{name}/{name}.vcxproj.user".format(name=pkg, vs=vs)
        if os.path.exists(vxproj_path):
            f = open(vxproj_path, "r")
            content = f.read()
            content = re.sub(r"<TestCertificate>.*</TestCertificate>",
                    "<TestCertificate>{}</TestCertificate>".format(path),
                    content)
            f.close()
            # break the link
            os.unlink(vxproj_path)
            f = open(vxproj_path, "w")
            f.write(content)
            f.close()

class msbuild_failure(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


def msbuild(platform, configuration, target, file, args, dir):
    os.environ['PLATFORM'] = platform
    os.environ['CONFIGURATION'] = configuration
    os.environ['TARGET'] = target
    os.environ['FILE'] = file
    os.environ['EXTRA'] = args

    bin = os.path.join(os.getcwd(), 'msbuild.bat')

    status = shell([bin], dir)

    if (status != 0):
        raise msbuild_failure(configuration)


def build_sln(name, release, arch, debug, vs):
    configuration = get_configuration(release, debug)

    if arch == 'x86':
        platform = 'Win32'
    elif arch == 'x64':
        platform = 'x64'

    cwd = os.getcwd()

    msbuild(platform, configuration, 'Build', name + '.sln', '', vs)


def manifest():
    cmd = ['git', 'ls-tree', '-r', '--name-only', 'HEAD']

    sub = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = sub.communicate()[0]
    ret = sub.returncode

    if ret != 0:
        raise(Exception("Error %d in : %s" % (ret, cmd)))

    return output.decode('utf-8')


def getVsVersion():
    vsenv ={} 
    vars = subprocess.check_output([os.environ['VS_PATH']+'\\VC\\vcvarsall.bat', '&&', 'set'], shell=True)
    for var in vars.splitlines():
        k, _, v = map(str.strip, var.strip().decode('utf-8').partition('='))
        if k.startswith('?'):
            continue
        vsenv[k] = v

    if vsenv['VisualStudioVersion'] == '11.0' :
        return 'vs2012'
    elif vsenv['VisualStudioVersion'] == '12.0' :
        return 'vs2013'

if __name__ == '__main__':
    driver = sys.argv[1]
    config = sys.argv[2]
    arch = sys.argv[3]
    debug = { 'chk': True, 'fre': False }
    vs = getVsVersion()

    if 'COMPANY_NAME' not in os.environ.keys():
        os.environ['COMPANY_NAME'] = 'Xen Project'

    if 'PRODUCT_NAME' not in os.environ.keys():
        os.environ['PRODUCT_NAME'] = 'Xen'

    os.environ['MAJOR_VERSION'] = '8'
    os.environ['MINOR_VERSION'] = '0'
    os.environ['MICRO_VERSION'] = '0'

    if 'BUILD_NUMBER' not in os.environ.keys():
        os.environ['BUILD_NUMBER'] = next_build_number()

    print("BUILD_NUMBER=%s" % os.environ['BUILD_NUMBER'])

    if 'GIT_REVISION' in os.environ.keys():
        revision = open('revision', 'w')
        print(os.environ['GIT_REVISION'], file=revision)
        revision.close()

    if 'CERT_FILENAME' in os.environ:
        update_cert_path(driver, vs, os.environ['CERT_FILENAME'])

    if vs=='vs2012':
        release = 'Windows Vista'
    else:
        release = 'Windows 7'

    build_sln(driver, release, arch, debug[config], vs)

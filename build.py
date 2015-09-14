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


def make_header():
    now = datetime.datetime.now()

    file = open('include\\version.h', 'w')

    file.write('#define VENDOR_NAME_STR\t\t"' + os.environ['VENDOR_NAME'] + '"\n')
    file.write('#define VENDOR_PREFIX_STR\t"' + os.environ['VENDOR_PREFIX'] + '"\n')

    if 'VENDOR_DEVICE_ID' in os.environ.keys():
        file.write('#define VENDOR_DEVICE_ID_STR\t"' + os.environ['VENDOR_DEVICE_ID'] + '"\n')

    file.write('#define PRODUCT_NAME_STR\t"' + os.environ['PRODUCT_NAME'] + '"\n')
    file.write('\n')

    file.write('#define OBJECT_PREFIX_STR\t"' + os.environ['OBJECT_PREFIX'] + '"\n')
    file.write('#define OBJECT_GUID(_Name)\t' + os.environ['OBJECT_PREFIX'] + ' ## _Name ## _GUID\n')
    file.write('\n')

    file.write('#define MAJOR_VERSION\t\t' + os.environ['MAJOR_VERSION'] + '\n')
    file.write('#define MAJOR_VERSION_STR\t"' + os.environ['MAJOR_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define MINOR_VERSION\t\t' + os.environ['MINOR_VERSION'] + '\n')
    file.write('#define MINOR_VERSION_STR\t"' + os.environ['MINOR_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define MICRO_VERSION\t\t' + os.environ['MICRO_VERSION'] + '\n')
    file.write('#define MICRO_VERSION_STR\t"' + os.environ['MICRO_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define BUILD_NUMBER\t\t' + os.environ['BUILD_NUMBER'] + '\n')
    file.write('#define BUILD_NUMBER_STR\t"' + os.environ['BUILD_NUMBER'] + '"\n')
    file.write('\n')

    file.write('#define YEAR\t\t\t' + str(now.year) + '\n')
    file.write('#define YEAR_STR\t\t"' + str(now.year) + '"\n')
    file.write('\n')

    file.write('#define MONTH\t\t\t' + str(now.month) + '\n')
    file.write('#define MONTH_STR\t\t"' + str(now.month) + '"\n')
    file.write('\n')

    file.write('#define DAY\t\t\t' + str(now.day) + '\n')
    file.write('#define DAY_STR\t\t\t"' + str(now.day) + '"\n')
    file.write('\n')

    file.close()


def copy_inf(vs, name):
    src = open('src\\%s.inf' % name, 'r')
    dst = open('%s\\%s.inf' % (vs, name), 'w')

    for line in src:
        line = re.sub('@MAJOR_VERSION@', os.environ['MAJOR_VERSION'], line)
        line = re.sub('@MINOR_VERSION@', os.environ['MINOR_VERSION'], line)
        line = re.sub('@MICRO_VERSION@', os.environ['MICRO_VERSION'], line)
        line = re.sub('@BUILD_NUMBER@', os.environ['BUILD_NUMBER'], line)
        line = re.sub('@VENDOR_NAME@', os.environ['VENDOR_NAME'], line)
        line = re.sub('@VENDOR_PREFIX@', os.environ['VENDOR_PREFIX'], line)
        line = re.sub('@PRODUCT_NAME@', os.environ['PRODUCT_NAME'], line)

        if re.search('@VENDOR_DEVICE_ID@', line):
            if 'VENDOR_DEVICE_ID' not in os.environ.keys():
                continue
            line = re.sub('@VENDOR_DEVICE_ID@', os.environ['VENDOR_DEVICE_ID'], line)

        dst.write(line)

    dst.close()
    src.close()


def copy_mof(name):
    src = open('src\\%s.mof' % name, 'r')
    dst = open('src\\%s\\wmi.mof' % name, 'w')

    for line in src:
        line = re.sub('@OBJECT_PREFIX@', os.environ['OBJECT_PREFIX'], line)
        dst.write(line)

    dst.close()
    src.close()


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

    if 'VENDOR_NAME' not in os.environ.keys():
        os.environ['VENDOR_NAME'] = 'Xen Project'

    if 'VENDOR_PREFIX' not in os.environ.keys():
        os.environ['VENDOR_PREFIX'] = 'XP'

    if 'PRODUCT_NAME' not in os.environ.keys():
        os.environ['PRODUCT_NAME'] = 'Xen'

    if 'OBJECT_PREFIX' not in os.environ.keys():
        os.environ['OBJECT_PREFIX'] = 'XenProject'

    os.environ['MAJOR_VERSION'] = '8'
    os.environ['MINOR_VERSION'] = '2'
    os.environ['MICRO_VERSION'] = '0'

    if 'BUILD_NUMBER' not in os.environ.keys():
        os.environ['BUILD_NUMBER'] = next_build_number()

    if 'GIT_REVISION' in os.environ.keys():
        revision = open('revision', 'w')
        print(os.environ['GIT_REVISION'], file=revision)
        revision.close()

    if 'CERT_FILENAME' in os.environ:
        update_cert_path(driver, vs, os.environ['CERT_FILENAME'])

    print("VENDOR_NAME\t\t'%s'" % os.environ['VENDOR_NAME'])
    print("VENDOR_PREFIX\t\t'%s'" % os.environ['VENDOR_PREFIX'])

    if 'VENDOR_DEVICE_ID' in os.environ.keys():
        print("VENDOR_DEVICE_ID\t'%s'" % os.environ['VENDOR_DEVICE_ID'])

    print("PRODUCT_NAME\t\t'%s'" % os.environ['PRODUCT_NAME'])
    print("MAJOR_VERSION\t\t%s" % os.environ['MAJOR_VERSION'])
    print("MINOR_VERSION\t\t%s" % os.environ['MINOR_VERSION'])
    print("MICRO_VERSION\t\t%s" % os.environ['MICRO_VERSION'])
    print("BUILD_NUMBER\t\t%s" % os.environ['BUILD_NUMBER'])
    print()

    make_header()
    copy_inf(vs, driver)

    if driver=='xeniface':
        copy_mof(driver)

    if vs=='vs2012':
        release = 'Windows Vista'
    else:
        release = 'Windows 7'

    build_sln(driver, release, arch, debug[config], vs)
